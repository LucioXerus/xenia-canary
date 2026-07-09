/**
 ******************************************************************************
 * Xenia : Xbox 360 Emulator Research Project                                 *
 ******************************************************************************
 * Copyright 2026 Ben Vanik. All rights reserved.                             *
 * Released under the BSD license - see LICENSE in the root for more details. *
 ******************************************************************************
 */

#include "xenia/cpu/backend/x64/x64_aot_cache.h"

#include <atomic>
#include <cstring>
#include <vector>

#include <dlfcn.h>

#include "xenia/base/filesystem.h"
#include "xenia/base/logging.h"
#include "xenia/base/xxhash.h"
#include "xenia/cpu/backend/x64/x64_backend.h"
#include "xenia/cpu/backend/x64/x64_code_cache.h"
#include "xenia/cpu/backend/x64/x64_emitter.h"
#include "xenia/cpu/backend/x64/x64_function.h"
#include "xenia/cpu/backend/x64/x64_stack_layout.h"
#include "xenia/cpu/export_resolver.h"
#include "xenia/cpu/function.h"
#include "xenia/cpu/module.h"
#include "xenia/cpu/processor.h"

namespace xe {
namespace cpu {
namespace backend {
namespace x64 {

static constexpr uint32_t kMagic = 'XAOT';
static constexpr uint32_t kVersion = 4;  // v4: store emitter_data base

#pragma pack(push, 1)
struct AOTFileHeader {
  uint32_t magic;
  uint32_t version;
  uint64_t abi_hash;
  uint32_t title_id;
  uint8_t module_hash[20];
  uint64_t emitter_data_base;  // host VA of const data at capture time
  uint32_t func_count;
};

struct AOTFuncHeader {
  uint32_t guest_address;
  uint32_t guest_code_size;  // guest PPC byte length (for hash validation)
  uint64_t guest_code_hash;
  uint32_t code_size;
  size_t code_size_prolog;
  size_t code_size_body;
  size_t code_size_epilog;
  size_t code_size_tail;
  size_t code_size_total;
  size_t prolog_stack_alloc_offset;
  size_t stack_size;
  uint32_t reloc_count;
  // Followed by:
  //   AOTRelocDisk[reloc_count]
  //   uint8_t[code_size] (code blob)
  //   uint32_t symtab_strings_size
  //   char[symtab_strings_size]
};

struct AOTRelocDisk {
  uint32_t offset;
  uint16_t kind;
  uint16_t width;
  int64_t addend;
  uint32_t symbol_id;
};
#pragma pack(pop)

struct X64AOTCache::BufferedFunction {
  uint32_t guest_address;
  uint32_t guest_code_size = 0;
  uint64_t guest_code_hash;
  std::vector<uint8_t> code_blob;
  EmitFunctionInfo emit_info;
  std::vector<AOTReloc> relocs;
  std::vector<std::string> symtab;
};

struct X64AOTCache::BufferedModule {
  uint32_t title_id = 0;
  uint8_t module_hash[20] = {};
  std::vector<std::unique_ptr<BufferedFunction>> functions;
};

// ---- AOTSymbolRegistry ----

void AOTSymbolRegistry::RegisterHostAddress(const std::string& key,
                                            void* host_addr) {
  addr_to_key_[reinterpret_cast<uintptr_t>(host_addr)] = key;
  key_to_addr_[key] = host_addr;
}

bool AOTSymbolRegistry::KeyForHostAddress(void* host_addr,
                                          std::string* out_key) const {
  auto it = addr_to_key_.find(reinterpret_cast<uintptr_t>(host_addr));
  if (it == addr_to_key_.end()) {
    return false;
  }
  *out_key = it->second;
  return true;
}

void* AOTSymbolRegistry::HostAddressForKey(const std::string& key) const {
  auto it = key_to_addr_.find(key);
  return it == key_to_addr_.end() ? nullptr : it->second;
}

// ---- AOTRecorder ----

void AOTRecorder::Begin() {
  active_ = true;
  relocs_.clear();
  symbol_table_.clear();
  symbol_index_.clear();
  failed_ = false;
}

void AOTRecorder::Reset() {
  active_ = false;
  relocs_.clear();
  symbol_table_.clear();
  symbol_index_.clear();
  failed_ = false;
}

uint32_t AOTRecorder::InternSymbol(const std::string& key) {
  auto it = symbol_index_.find(key);
  if (it != symbol_index_.end()) {
    return it->second;
  }
  uint32_t id = static_cast<uint32_t>(symbol_table_.size());
  symbol_table_.push_back(key);
  symbol_index_[key] = id;
  return id;
}

void AOTRecorder::RecordInternal(uint32_t code_offset, void* host_addr,
                                 AOTRelocKind kind, uint16_t width,
                                 int64_t addend) {
  if (!active_ || failed_) {
    return;
  }
  if (!host_addr) {
    // A baked literal null pointer (e.g. a builtin with no arg0/arg1) is
    // position-independent — the immediate is 0 in every session — so it needs
    // no relocation and must NOT fail the function.
    return;
  }
  std::string key;
  if (!symbols_->KeyForHostAddress(host_addr, &key)) {
    // Unknown host target -> this function is not safely cacheable.
#if 1  // AOT-DIAG: identify unregistered bake sites (remove after diagnosis).
    static std::atomic<int> diag_count{0};
    int n = diag_count.fetch_add(1);
    if (n < 40) {
      Dl_info info;
      const char* sym = "?";
      const char* lib = "?";
      if (dladdr(host_addr, &info)) {
        if (info.dli_sname) {
          sym = info.dli_sname;
        }
        if (info.dli_fname) {
          lib = info.dli_fname;
        }
      }
      XELOGE(
          "AOT-DIAG: unregistered host ptr {} kind={} -> sym='{}' lib='{}' "
          "(function marked uncacheable)",
          host_addr, static_cast<int>(kind), sym, lib);
    }
#endif
    failed_ = true;
    return;
  }
  relocs_.push_back({code_offset, kind, width, addend, InternSymbol(key)});
}

void AOTRecorder::RecordHostPtr(uint32_t end_offset, void* host_addr,
                                int64_t addend) {
  // xbyak encodes `mov r64, imm` in one of three forms, chosen by the value
  // and the destination register. The immediate is ALWAYS the trailing field
  // of the instruction, so the imm starts at (end_offset - width):
  //   * value <= 0xFFFFFFFF, reg in r0-r7  -> 5-byte  `B8+rd imm32`    (width
  //   4)
  //   * value <= 0xFFFFFFFF, reg in r8-r15 -> 6-byte  `REX.B B8+rd imm32`
  //   (width 4)
  //   * value >  0xFFFFFFFF                -> 10-byte `REX.W B8+rd imm64`
  //   (width 8)
  // The earlier "+2 then -1" heuristic assumed no REX on the 5-byte form,
  // which is FALSE for r8-r15 (they always need REX.B). For those it computed
  // the imm offset one byte too low, landing on the opcode byte, so ApplyRelocs
  // overwrote the opcode on reload and corrupted the instruction (black screen
  // on the 2nd run). Deriving the offset from the instruction END is robust to
  // all REX variants.
  uint64_t value = reinterpret_cast<uint64_t>(host_addr) + addend;
  if (value <= 0xFFFFFFFFULL) {
    RecordInternal(end_offset - 4, host_addr, AOTRelocKind::kAbs64HostPtr, 4,
                   addend);
  } else {
    RecordInternal(end_offset - 8, host_addr, AOTRelocKind::kAbs64HostPtr, 8,
                   addend);
  }
}

void AOTRecorder::RecordAbsData32(uint32_t code_offset, void* host_addr,
                                  int64_t addend) {
  RecordInternal(code_offset, host_addr, AOTRelocKind::kAbsData32, 4, addend);
}

void AOTRecorder::RecordRel32HostCall(uint32_t code_offset, void* host_addr,
                                      int64_t addend) {
  RecordInternal(code_offset, host_addr, AOTRelocKind::kRel32HostCall, 4,
                 addend);
}

void AOTRecorder::TakeData(std::vector<AOTReloc>* out_relocs,
                           std::vector<std::string>* out_symtab) {
  *out_relocs = std::move(relocs_);
  *out_symtab = std::move(symbol_table_);
  Reset();
}

// ---- X64AOTCache ----

X64AOTCache::X64AOTCache(X64Backend* backend, X64CodeCache* code_cache)
    : backend_(backend), code_cache_(code_cache) {}

X64AOTCache::~X64AOTCache() { FlushAll(); }

uint64_t X64AOTCache::ABIHash() {
  // Bump this literal whenever the emitter, sequences, or X64BackendContext
  // change in a way that invalidates cached native code.
  uint64_t hash = 0x0000000000010006ull;  // bump: fix RecordHostPtr imm offset
                                          // for REX-prefixed extended regs
                                          // (r8-r15); old caches have relocs at
                                          // the wrong offset and would corrupt
                                          // opcodes on reload.
  hash ^= static_cast<uint64_t>(sizeof(X64BackendContext));
  // Mix explicit StackLayout offsets so stack-frame changes invalidate.
  hash ^= static_cast<uint64_t>(StackLayout::GUEST_STACK_SIZE);
  hash ^= (static_cast<uint64_t>(StackLayout::GUEST_RET_ADDR) << 16);
  hash ^= (static_cast<uint64_t>(StackLayout::GUEST_CALL_RET_ADDR) << 32);
  return hash;
}

bool X64AOTCache::Initialize(const std::filesystem::path& cache_root) {
  cache_root_ = cache_root;
  std::error_code ec;
  std::filesystem::create_directories(cache_root_, ec);
  if (ec) {
    XELOGE("AOT: Failed to create cache directory: {}", ec.message());
    return false;
  }

  auto& s = symbols_;
  s.RegisterHostAddress(
      "thunk.host_to_guest",
      reinterpret_cast<void*>(backend_->host_to_guest_thunk()));
  s.RegisterHostAddress(
      "thunk.guest_to_host",
      reinterpret_cast<void*>(backend_->guest_to_host_thunk()));
  s.RegisterHostAddress(
      "thunk.resolve_function",
      reinterpret_cast<void*>(backend_->resolve_function_thunk()));

  s.RegisterHostAddress("helper.try_acquire_reservation",
                        backend_->try_acquire_reservation_helper_);
  s.RegisterHostAddress("helper.reserved_store_32",
                        backend_->reserved_store_32_helper);
  s.RegisterHostAddress("helper.reserved_store_64",
                        backend_->reserved_store_64_helper);
  s.RegisterHostAddress("helper.vrsqrtefp_vector",
                        backend_->vrsqrtefp_vector_helper);
  s.RegisterHostAddress("helper.vrsqrtefp_scalar",
                        backend_->vrsqrtefp_scalar_helper);
  s.RegisterHostAddress("helper.frsqrtefp", backend_->frsqrtefp_helper);
  s.RegisterHostAddress(
      "helper.sync_stack",
      reinterpret_cast<void*>(
          backend_->synchronize_guest_and_host_stack_helper()));
  s.RegisterHostAddress(
      "helper.sync_stack_8",
      reinterpret_cast<void*>(
          backend_->synchronize_guest_and_host_stack_helper_for_size(1)));
  s.RegisterHostAddress(
      "helper.sync_stack_16",
      reinterpret_cast<void*>(
          backend_->synchronize_guest_and_host_stack_helper_for_size(2)));
  s.RegisterHostAddress(
      "helper.sync_stack_32",
      reinterpret_cast<void*>(
          backend_->synchronize_guest_and_host_stack_helper_for_size(4)));
  s.RegisterHostAddress("data.emitter",
                        reinterpret_cast<void*>(backend_->emitter_data()));
  // Baked into every function prolog's stackpoint-overflow tail. Without this
  // key, RecordHostPtr fails for that site and marks EVERY function
  // uncacheable.
  s.RegisterHostAddress("helper.stackpoint_overflow",
                        X64Emitter::stackpoint_overflow_handler_address());

  enabled_ = true;
  XELOGCPU("AOT: Cache initialized at {} (emitter_data base {:#x})",
           cache_root_.string(), backend_->emitter_data());
  return true;
}

// Builds the stable relocation key for an extern (kernel-export) handler.
// The export's name + ordinal are stable across runs; the handler *address*
// is not (it lives in the ASLR'd Xenia binary). Keying by identity lets us
// rebind to the current address on reload.
static std::string ExternSymbolKey(Export* export_data) {
  if (export_data && export_data->name && export_data->name[0]) {
    return fmt::format("extern:{}:{}", export_data->name, export_data->ordinal);
  }
  // No name available: fall back to ordinal only. (Unnamed exports.)
  return fmt::format("extern:#{}",
                     export_data ? export_data->ordinal : uint16_t(0));
}

void X64AOTCache::RegisterDynamicSymbols(Processor* processor) {
  if (!processor) {
    return;
  }
  auto& s = symbols_;
  size_t builtins = 0;
  size_t externs = 0;

  // Builtin handlers (CheckGlobalLock/EnterGlobalLock/LeaveGlobalLock/
  // SyscallHandler, plus any others). handler_/arg0_/arg1_ are raw host
  // pointers with stable identity tied to the builtin's (fixed) name.
  if (auto* builtin_module = processor->builtin_module()) {
    builtin_module->ForEachFunction([&](Function* fn) {
      if (!fn || fn->behavior() != Function::Behavior::kBuiltin) {
        return;
      }
      auto* bf = static_cast<BuiltinFunction*>(fn);
      if (!bf->handler()) {
        return;
      }
      const std::string& name = fn->name();
      s.RegisterHostAddress("builtin.h:" + name,
                            reinterpret_cast<void*>(bf->handler()));
      if (bf->arg0()) {
        s.RegisterHostAddress("builtin.a0:" + name, bf->arg0());
      }
      if (bf->arg1()) {
        s.RegisterHostAddress("builtin.a1:" + name, bf->arg1());
      }
      ++builtins;
    });
  }

  // Extern (kernel-export) handlers. These live in the main xex module
  // (resolved imports) and in kernel trampoline modules. Key by the export's
  // name+ordinal so the same key maps to the current handler each run.
  for (Module* module : processor->GetModules()) {
    if (!module) {
      // GetModules() pads with nullptrs; skip them.
      continue;
    }
    module->ForEachFunction([&](Function* fn) {
      if (!fn || fn->behavior() != Function::Behavior::kExtern) {
        return;
      }
      auto* gf = static_cast<GuestFunction*>(fn);
      auto handler = gf->extern_handler();
      if (!handler) {
        return;
      }
      s.RegisterHostAddress(ExternSymbolKey(gf->export_data()),
                            reinterpret_cast<void*>(handler));
      ++externs;
    });
  }

  XELOGCPU("AOT: Registered {} builtin and {} extern handler symbols", builtins,
           externs);
}

void X64AOTCache::CaptureFunction(
    uint32_t guest_address, uint32_t guest_code_size, const void* machine_code,
    const EmitFunctionInfo& info, uint64_t guest_code_hash,
    uintptr_t module_key, uint32_t title_id, const uint8_t module_hash[20],
    AOTRecorder* recorder) {
#if 1  // AOT-DIAG: capture attempt accounting (remove after diagnosis).
  static std::atomic<uint64_t> diag_attempts{0};
  static std::atomic<uint64_t> diag_failed{0};
  static std::atomic<uint64_t> diag_inactive{0};
  static std::atomic<uint64_t> diag_captured{0};
  uint64_t attempt = diag_attempts.fetch_add(1) + 1;
  if (enabled_ && recorder && recorder->active() && recorder->failed()) {
    diag_failed.fetch_add(1);
  } else if (!enabled_ || !recorder || !recorder->active()) {
    diag_inactive.fetch_add(1);
  }
  if ((attempt % 2000) == 0) {
    XELOGCPU(
        "AOT-DIAG: capture attempts={} captured={} failed(reloc)={} "
        "inactive/disabled={}",
        attempt, diag_captured.load(), diag_failed.load(),
        diag_inactive.load());
  }
#endif
  if (!enabled_ || !recorder || !recorder->active() || recorder->failed()) {
    if (recorder) {
      recorder->Reset();
    }
    return;
  }
#if 1
  diag_captured.fetch_add(1);
#endif

  auto bf = std::make_unique<BufferedFunction>();
  bf->guest_address = guest_address;
  bf->guest_code_size = guest_code_size;
  bf->guest_code_hash = guest_code_hash;
  size_t total_size = info.code_size.total;
  bf->code_blob.assign(static_cast<const uint8_t*>(machine_code),
                       static_cast<const uint8_t*>(machine_code) + total_size);
  bf->emit_info = info;
  recorder->TakeData(&bf->relocs, &bf->symtab);

  auto global_lock = global_critical_region_.Acquire();

  auto& mod = pending_[module_key];
  if (!mod) {
    mod = std::make_unique<BufferedModule>();
  }
  mod->title_id = title_id;
  std::memcpy(mod->module_hash, module_hash, 20);
  mod->functions.push_back(std::move(bf));
}

bool X64AOTCache::ApplyRelocs(uint8_t* write_base, uintptr_t exec_base,
                              size_t code_size,
                              const std::vector<AOTReloc>& relocs,
                              const std::vector<std::string>& symtab) {
  for (const auto& r : relocs) {
    // Bounds check: offset + width must fit within the code blob (H1).
    if (r.offset > code_size || (code_size - r.offset) < r.width) {
      XELOGE("AOT: Reloc offset {} width {} out of bounds (code_size {})",
             r.offset, r.width, code_size);
      return false;
    }
    if (r.symbol_id >= symtab.size()) {
      XELOGE("AOT: Reloc symbol_id {} out of range", r.symbol_id);
      return false;
    }
    void* host = symbols_.HostAddressForKey(symtab[r.symbol_id]);
    if (!host) {
      XELOGE("AOT: Symbol '{}' not found in registry", symtab[r.symbol_id]);
      return false;
    }

    uint8_t* dst = write_base + r.offset;
    uint64_t symbol_now = reinterpret_cast<uint64_t>(host);

    switch (r.kind) {
      case AOTRelocKind::kAbs64HostPtr: {
        uint64_t value = symbol_now + static_cast<uint64_t>(r.addend);
        // Honor the recorded width: a `mov r64, imm` that xbyak
        // encoded as the 5-byte `B8+rd imm32` form (value <= 0xFFFFFFFF)
        // only carries a 4-byte immediate. Writing 8 bytes here would
        // clobber the following instruction (previously the cause of a
        // black screen on the 2nd, reloaded run).
        if (r.width == 4) {
          if (value > 0xFFFFFFFFULL) {
            XELOGE(
                "AOT: reloc value {:x} does not fit the 4-byte slot "
                "recorded at offset {}",
                value, r.offset);
            return false;
          }
          uint32_t v = static_cast<uint32_t>(value);
          std::memcpy(dst, &v, sizeof(uint32_t));
        } else {
          std::memcpy(dst, &value, sizeof(uint64_t));
        }
        break;
      }
      case AOTRelocKind::kAbsData32: {
        uint32_t value =
            static_cast<uint32_t>(symbol_now + static_cast<uint64_t>(r.addend));
        if (r.width == 4) {
          std::memcpy(dst, &value, sizeof(uint32_t));
        } else {
          // Defensive: data refs are always disp32 (width 4). A wider
          // record is unexpected; refuse to write past the slot.
          XELOGE("AOT: kAbsData32 with unexpected width {}", r.width);
          return false;
        }
        break;
      }
      case AOTRelocKind::kRel32HostCall: {
        // disp = (symbol_now + addend) - (exec_base + reloc_offset + 4)
        int64_t target = static_cast<int64_t>(symbol_now + r.addend);
        int64_t next_instr = static_cast<int64_t>(exec_base + r.offset + 4);
        int32_t disp = static_cast<int32_t>(target - next_instr);
        std::memcpy(dst, &disp, sizeof(int32_t));
        break;
      }
      default:
        XELOGE("AOT: Unknown reloc kind {}", static_cast<uint16_t>(r.kind));
        return false;
    }
  }
  return true;
}

static std::string ModuleHashStr(const uint8_t module_hash[20]) {
  std::string s;
  s.reserve(40);
  for (int i = 0; i < 20; ++i) {
    s += fmt::format("{:02X}", module_hash[i]);
  }
  return s;
}

static std::filesystem::path ModuleCachePath(
    const std::filesystem::path& cache_root, const uint8_t module_hash[20]) {
  return cache_root / (ModuleHashStr(module_hash) + ".xaot");
}

// Advances the file pointer past the relocs/code/symtab of one function
// record (the part following the AOTFuncHeader). Used when merging to skip an
// existing record that is superseded by a fresh capture.
static bool SkipFunctionRecord(FILE* f, const AOTFuncHeader& fh) {
  if (fh.reloc_count) {
    if (fseek(f, static_cast<long>(fh.reloc_count * sizeof(AOTRelocDisk)),
              SEEK_CUR) != 0) {
      return false;
    }
  }
  if (fh.code_size) {
    if (fseek(f, static_cast<long>(fh.code_size), SEEK_CUR) != 0) {
      return false;
    }
  }
  uint32_t symtab_size = 0;
  if (fread(&symtab_size, sizeof(symtab_size), 1, f) != 1) {
    return false;
  }
  if (symtab_size) {
    if (fseek(f, static_cast<long>(symtab_size), SEEK_CUR) != 0) {
      return false;
    }
  }
  return true;
}

// Reads the relocs/code/symtab following an AOTFuncHeader into a
// BufferedFunction (the fields the merge needs to re-serialize the record).
static bool ReadFunctionBody(FILE* f, const AOTFuncHeader& fh,
                             std::vector<AOTReloc>& relocs,
                             std::vector<uint8_t>& code_blob,
                             std::vector<std::string>& symtab) {
  if (fh.reloc_count) {
    std::vector<AOTRelocDisk> disk(fh.reloc_count);
    if (fread(disk.data(), sizeof(AOTRelocDisk), fh.reloc_count, f) !=
        fh.reloc_count) {
      return false;
    }
    relocs.reserve(fh.reloc_count);
    for (const auto& rd : disk) {
      relocs.push_back({rd.offset, static_cast<AOTRelocKind>(rd.kind), rd.width,
                        rd.addend, rd.symbol_id});
    }
  }
  if (fh.code_size) {
    code_blob.resize(fh.code_size);
    if (fread(code_blob.data(), fh.code_size, 1, f) != 1) {
      return false;
    }
  }
  uint32_t symtab_size = 0;
  if (fread(&symtab_size, sizeof(symtab_size), 1, f) != 1) {
    return false;
  }
  if (symtab_size) {
    std::vector<char> raw(symtab_size);
    if (fread(raw.data(), symtab_size, 1, f) != 1) {
      return false;
    }
    size_t pos = 0;
    while (pos < raw.size()) {
      const char* start = raw.data() + pos;
      size_t len = strlen(start);
      symtab.emplace_back(start);
      pos += len + 1;
    }
  }
  return true;
}

// Write buffered functions to disk for one module via a temp file + atomic
// rename, so a partial write never truncates an existing good cache file.
//
// Merge semantics: a warm run preloads N functions from the existing cache,
// then JITs a small number of newly-touched functions. At shutdown we must
// MERGE those new captures into the on-disk cache — NOT replace it — or every
// warm run wipes the accumulated cache (the cause of a cache that never grew
// past a single session's fresh compiles). Functions present in BOTH the
// existing file and the new batch are kept from the new batch (it's a fresh
// capture; the bytes/relocs are authoritative).
void X64AOTCache::FlushModule(
    uint32_t title_id, const uint8_t module_hash[20],
    std::vector<std::unique_ptr<BufferedFunction>>&& functions) {
  if (functions.empty()) {
    return;
  }

  auto path = ModuleCachePath(cache_root_, module_hash);
  std::error_code ec;
  std::filesystem::create_directories(path.parent_path(), ec);

  // Index the new captures by guest_address for dedup against the existing
  // file (new captures win on conflict).
  std::unordered_map<uint32_t, size_t> new_index;
  new_index.reserve(functions.size());
  for (size_t i = 0; i < functions.size(); ++i) {
    new_index[functions[i]->guest_address] = i;
  }

  // Load the existing cache file and append any functions NOT present in the
  // new batch. This is what makes the cache grow across sessions.
  std::vector<std::unique_ptr<BufferedFunction>> merged;
  merged.reserve(functions.size());
  for (auto& fn : functions) {
    merged.push_back(std::move(fn));
  }
  functions.clear();

  FILE* existing = xe::filesystem::OpenFile(path, "rb");
  size_t kept_from_existing = 0;
  size_t skipped_stale = 0;
  if (existing) {
    AOTFileHeader ex_header;
    if (fread(&ex_header, sizeof(ex_header), 1, existing) == 1 &&
        ex_header.magic == kMagic && ex_header.version == kVersion &&
        ex_header.abi_hash == ABIHash()) {
      for (uint32_t i = 0; i < ex_header.func_count; ++i) {
        AOTFuncHeader fh;
        if (fread(&fh, sizeof(fh), 1, existing) != 1) {
          XELOGE("AOT: Truncated existing cache at function {}", i);
          break;
        }
        // Skip if the new batch already recaptured this address.
        if (new_index.count(fh.guest_address)) {
          // Discard the existing record's body but still advance the file
          // pointer past its relocs/code/symtab.
          if (!SkipFunctionRecord(existing, fh)) {
            break;
          }
          ++skipped_stale;
          continue;
        }
        auto bf = std::make_unique<BufferedFunction>();
        bf->guest_address = fh.guest_address;
        bf->guest_code_size = fh.guest_code_size;
        bf->guest_code_hash = fh.guest_code_hash;
        if (!ReadFunctionBody(existing, fh, bf->relocs, bf->code_blob,
                              bf->symtab)) {
          XELOGE("AOT: Truncated existing cache body at function {}", i);
          break;
        }
        bf->emit_info.code_size.prolog = fh.code_size_prolog;
        bf->emit_info.code_size.body = fh.code_size_body;
        bf->emit_info.code_size.epilog = fh.code_size_epilog;
        bf->emit_info.code_size.tail = fh.code_size_tail;
        bf->emit_info.code_size.total = fh.code_size_total;
        bf->emit_info.prolog_stack_alloc_offset = fh.prolog_stack_alloc_offset;
        bf->emit_info.stack_size = fh.stack_size;
        merged.push_back(std::move(bf));
        ++kept_from_existing;
      }
    }
    fclose(existing);
  }

  // Write to a temp file then atomically rename.
  auto tmp_path = path;
  tmp_path += ".tmp";
  FILE* f = xe::filesystem::OpenFile(tmp_path, "wb");
  if (!f) {
    XELOGE("AOT: Cannot write cache file {}", tmp_path.string());
    return;
  }

  AOTFileHeader header = {};
  header.magic = kMagic;
  header.version = kVersion;
  header.abi_hash = ABIHash();
  header.title_id = title_id;
  std::memcpy(header.module_hash, module_hash, 20);
  header.emitter_data_base = backend_->emitter_data();
  header.func_count = static_cast<uint32_t>(merged.size());

  if (fwrite(&header, sizeof(header), 1, f) != 1) {
    fclose(f);
    XELOGE("AOT: Failed to write header to {}", tmp_path.string());
    return;
  }

  size_t written = 0;
  for (const auto& fn : merged) {
    AOTFuncHeader fh = {};
    fh.guest_address = fn->guest_address;
    fh.guest_code_size = fn->guest_code_size;
    fh.guest_code_hash = fn->guest_code_hash;
    fh.code_size = static_cast<uint32_t>(fn->code_blob.size());
    fh.code_size_prolog = fn->emit_info.code_size.prolog;
    fh.code_size_body = fn->emit_info.code_size.body;
    fh.code_size_epilog = fn->emit_info.code_size.epilog;
    fh.code_size_tail = fn->emit_info.code_size.tail;
    fh.code_size_total = fn->emit_info.code_size.total;
    fh.prolog_stack_alloc_offset = fn->emit_info.prolog_stack_alloc_offset;
    fh.stack_size = fn->emit_info.stack_size;
    fh.reloc_count = static_cast<uint32_t>(fn->relocs.size());

    if (fwrite(&fh, sizeof(fh), 1, f) != 1) {
      XELOGE("AOT: Failed to write func header at {}", tmp_path.string());
      fclose(f);
      return;
    }

    // Write relocations.
    for (const auto& reloc : fn->relocs) {
      AOTRelocDisk rd;
      rd.offset = reloc.offset;
      rd.kind = static_cast<uint16_t>(reloc.kind);
      rd.width = reloc.width;
      rd.addend = reloc.addend;
      rd.symbol_id = reloc.symbol_id;
      if (fwrite(&rd, sizeof(rd), 1, f) != 1) {
        fclose(f);
        return;
      }
    }

    // Write code blob.
    if (!fn->code_blob.empty() &&
        fwrite(fn->code_blob.data(), fn->code_blob.size(), 1, f) != 1) {
      XELOGE("AOT: Failed to write code blob at {}", tmp_path.string());
      fclose(f);
      return;
    }

    // Write symbol table strings (null-separated).
    std::vector<char> symtab_data;
    for (const auto& s : fn->symtab) {
      symtab_data.insert(symtab_data.end(), s.begin(), s.end());
      symtab_data.push_back('\0');
    }
    uint32_t symtab_size = static_cast<uint32_t>(symtab_data.size());
    if (fwrite(&symtab_size, sizeof(symtab_size), 1, f) != 1) {
      fclose(f);
      return;
    }
    if (symtab_size && fwrite(symtab_data.data(), symtab_size, 1, f) != 1) {
      fclose(f);
      return;
    }

    ++written;
  }

  fclose(f);

  std::filesystem::rename(tmp_path, path, ec);
  if (ec) {
    // rename may fail across some filesystems; fall back to copy+remove.
    std::filesystem::copy_file(
        tmp_path, path, std::filesystem::copy_options::overwrite_existing, ec);
    if (!ec) {
      std::filesystem::remove(tmp_path, ec);
    }
  }
  XELOGCPU(
      "AOT: Flushed {} functions to {} ({} new + {} kept from existing, "
      "{} superseded)",
      written, path.string(), written - kept_from_existing, kept_from_existing,
      skipped_stale);
}

void X64AOTCache::FlushModuleForTeardown(uint32_t title_id,
                                         const uint8_t module_hash[20],
                                         uintptr_t module_key) {
  std::vector<std::unique_ptr<BufferedFunction>> functions;
  {
    auto global_lock = global_critical_region_.Acquire();
    auto it = pending_.find(module_key);
    if (it == pending_.end() || !it->second || it->second->functions.empty()) {
      return;
    }
    functions = std::move(it->second->functions);
    pending_.erase(it);
  }
  FlushModule(title_id, module_hash, std::move(functions));
}

void X64AOTCache::FlushAll() {
  // Move all pending buffers out under the lock, then write without holding it.
  std::vector<std::tuple<uint32_t, std::array<uint8_t, 20>,
                         std::vector<std::unique_ptr<BufferedFunction>>>>
      to_flush;
  {
    auto global_lock = global_critical_region_.Acquire();
    if (pending_.empty()) {
      return;
    }
    XELOGCPU("AOT: Flushing {} modules to disk", pending_.size());
    for (auto& [key, mod] : pending_) {
      if (!mod || mod->functions.empty()) {
        continue;
      }
      std::array<uint8_t, 20> hash_copy;
      std::memcpy(hash_copy.data(), mod->module_hash, 20);
      to_flush.emplace_back(mod->title_id, hash_copy,
                            std::move(mod->functions));
    }
    pending_.clear();
  }

  for (auto& [title_id, hash_arr, functions] : to_flush) {
    FlushModule(title_id, hash_arr.data(), std::move(functions));
  }
}

size_t X64AOTCache::PreloadModule(Module* module, uint32_t title_id,
                                  const uint8_t module_hash[20],
                                  ProgressCallback progress) {
  if (!enabled_) {
    return 0;
  }

  // Read the cache file and preload. (Pending functions are flushed at
  // shutdown/title-teardown, NOT here — lifecycle was inverted in the
  // original code which meant nothing was ever written.)
  auto path = ModuleCachePath(cache_root_, module_hash);
  FILE* f = xe::filesystem::OpenFile(path, "rb");
  if (!f) {
    XELOGCPU("AOT: No cache file at {}, JIT will be used", path.string());
    return 0;
  }

  AOTFileHeader header;
  if (fread(&header, sizeof(header), 1, f) != 1) {
    fclose(f);
    XELOGE("AOT: Failed to read header from {}", path.string());
    return 0;
  }

  if (header.magic != kMagic || header.version != kVersion ||
      header.abi_hash != ABIHash()) {
    fclose(f);
    XELOGCPU("AOT: Cache stale or incompatible for {}, will rebuild",
             path.string());
    return 0;
  }

  XELOGCPU("AOT: Preloading {} functions from {}", header.func_count,
           path.string());

  // The XMM/const-data region is referenced by absolute disp32 baked into the
  // cached code and is NOT relocated. If it landed at a different host VA this
  // run (AllocFixed falls back when 0x20000000 is occupied), every constant
  // load in the cached code would be wrong (black screen / bad math, no crash).
  uint64_t current_emitter_data = backend_->emitter_data();
  if (header.emitter_data_base != current_emitter_data) {
    XELOGE(
        "AOT: emitter_data base moved (cached {:#x} -> current {:#x}); cached "
        "const-data refs would be STALE. Skipping preload, will JIT.",
        header.emitter_data_base, current_emitter_data);
    fclose(f);
    return 0;
  }

  auto* memory = module->memory();
  size_t loaded = 0;

  for (uint32_t i = 0; i < header.func_count; ++i) {
    AOTFuncHeader fh;
    if (fread(&fh, sizeof(fh), 1, f) != 1) {
      XELOGE("AOT: Truncated file at function {}", i);
      break;
    }

    // Read relocations.
    std::vector<AOTReloc> relocs;
    std::vector<AOTRelocDisk> disk_relocs(fh.reloc_count);
    if (fh.reloc_count) {
      if (fread(disk_relocs.data(), sizeof(AOTRelocDisk), fh.reloc_count, f) !=
          fh.reloc_count) {
        XELOGE("AOT: Truncated relocs at function {}", i);
        break;
      }
      relocs.reserve(fh.reloc_count);
      for (const auto& rd : disk_relocs) {
        relocs.push_back({rd.offset, static_cast<AOTRelocKind>(rd.kind),
                          rd.width, rd.addend, rd.symbol_id});
      }
    }

    // Read code blob.
    std::vector<uint8_t> code_blob(fh.code_size);
    if (fh.code_size && fread(code_blob.data(), fh.code_size, 1, f) != 1) {
      XELOGE("AOT: Truncated code blob at function {}", i);
      break;
    }

    // Read symbol table.
    uint32_t symtab_bytes = 0;
    std::vector<std::string> symtab;
    if (fread(&symtab_bytes, sizeof(symtab_bytes), 1, f) != 1) {
      XELOGE("AOT: Truncated symtab size at function {}", i);
      break;
    }
    if (symtab_bytes) {
      std::vector<char> symtab_data(symtab_bytes);
      if (fread(symtab_data.data(), symtab_bytes, 1, f) != 1) {
        XELOGE("AOT: Truncated symtab data at function {}", i);
        break;
      }
      size_t pos = 0;
      while (pos < symtab_data.size()) {
        const char* start = symtab_data.data() + pos;
        size_t len = strlen(start);
        symtab.emplace_back(start);
        pos += len + 1;
      }
    }

    // Validate the guest PPC bytes against the cached hash. The guest code
    // size is stored in the cache file (computed at capture time), so this
    // does NOT depend on the function having been analyzed yet — at preload
    // (launch) most functions have not been discovered, so relying on an
    // existing symbol's end_address made almost every function fail here.
    uint32_t guest_code_size = fh.guest_code_size;
    if (!module->ContainsAddress(fh.guest_address)) {
      continue;
    }

    uint64_t current_hash = 0;
    if (guest_code_size > 0 && guest_code_size <= 65536) {
      const uint8_t* ppc_bytes =
          memory->TranslateVirtual<const uint8_t*>(fh.guest_address);
      if (ppc_bytes) {
        current_hash = XXH3_64bits(ppc_bytes, guest_code_size);
      }
    }

    if (current_hash != fh.guest_code_hash) {
      XELOGCPU("AOT: Function {:08X} hash mismatch, JIT will recompile",
               fh.guest_address);
      continue;
    }

    // Restore EmitFunctionInfo.
    EmitFunctionInfo emit_info = {};
    emit_info.code_size.prolog = fh.code_size_prolog;
    emit_info.code_size.body = fh.code_size_body;
    emit_info.code_size.epilog = fh.code_size_epilog;
    emit_info.code_size.tail = fh.code_size_tail;
    emit_info.code_size.total = fh.code_size_total;
    emit_info.prolog_stack_alloc_offset = fh.prolog_stack_alloc_offset;
    emit_info.stack_size = fh.stack_size;

    // Create/get the GuestFunction for this address.
    Function* fn = nullptr;
    auto sym_status = module->DeclareFunction(fh.guest_address, &fn);
    if (sym_status == Symbol::Status::kFailed || !fn || !fn->is_guest()) {
      continue;
    }
    auto* gf = static_cast<GuestFunction*>(fn);

    // Restore the guest end address (analysis normally sets this; at preload
    // the function is freshly declared, so set it from the cached size).
    if (guest_code_size > 0 && !gf->has_end_address()) {
      gf->set_end_address(fh.guest_address + guest_code_size);
    }

    // Place code into the cache (copies bytes, updates indirection table).
    void* exec = nullptr;
    void* write = nullptr;
    code_cache_->PlaceGuestCode(fh.guest_address, code_blob.data(), emit_info,
                                gf, exec, write);

    // Apply relocations in the writable view. rel32 disp is computed against
    // the execute-base address (the runtime PC). On this target the write and
    // execute views alias (writable-exec preferred), but pass both for
    // correctness on separate-view targets.
    if (!ApplyRelocs(reinterpret_cast<uint8_t*>(write),
                     reinterpret_cast<uintptr_t>(exec), code_blob.size(),
                     relocs, symtab)) {
      XELOGCPU("AOT: Failed to relocate {:08X}, will JIT", fh.guest_address);
      continue;
    }

    // Flush I-cache.
    code_cache_->FlushCodeRange(write, code_blob.size());

    // Setup the function with its machine code address.
    auto* x64_fn = static_cast<X64Function*>(gf);
    x64_fn->Setup(reinterpret_cast<uint8_t*>(exec), code_blob.size());

    // Mark as defined so Processor::ResolveFunction won't recompile.
    fn->set_status(Symbol::Status::kDefined);

    ++loaded;
    if (progress) {
      progress(loaded, header.func_count,
               fmt::format("Loading cached code ({:08X})", fh.guest_address));
    }
  }

  fclose(f);
  XELOGCPU("AOT: Preloaded {}/{} functions from {}", loaded, header.func_count,
           path.string());
  return loaded;
}

}  // namespace x64
}  // namespace backend
}  // namespace cpu
}  // namespace xe
