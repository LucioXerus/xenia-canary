/**
 ******************************************************************************
 * Xenia : Xbox 360 Emulator Research Project                                 *
 ******************************************************************************
 * Copyright 2026 Ben Vanik. All rights reserved.                             *
 * Released under the BSD license - see LICENSE in the root for more details. *
 ******************************************************************************
 */

#include "xenia/cpu/backend/x64/x64_aot_cache.h"

#include <cstring>
#include <vector>

#include "xenia/base/logging.h"
#include "xenia/base/xxhash.h"
#include "xenia/cpu/backend/x64/x64_backend.h"
#include "xenia/cpu/backend/x64/x64_code_cache.h"
#include "xenia/cpu/backend/x64/x64_function.h"
#include "xenia/cpu/function.h"
#include "xenia/cpu/module.h"

namespace xe {
namespace cpu {
namespace backend {
namespace x64 {

static constexpr uint32_t kMagic = 'XAOT';
static constexpr uint32_t kVersion = 1;

#pragma pack(push, 1)
struct AOTFileHeader {
  uint32_t magic;
  uint32_t version;
  uint64_t abi_hash;
  uint32_t title_id;
  uint8_t module_hash[20];
  uint32_t func_count;
};

struct AOTFuncHeader {
  uint32_t guest_address;
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
  uint64_t guest_code_hash;
  std::vector<uint8_t> code_blob;
  EmitFunctionInfo emit_info;
  std::vector<AOTReloc> relocs;
  std::vector<std::string> symtab;
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

void AOTRecorder::RecordHostPtr(uint32_t code_offset, void* host_addr,
                                AOTRelocKind kind, uint16_t width,
                                int64_t addend) {
  if (!active_ || failed_) {
    return;
  }
  std::string key;
  if (!symbols_->KeyForHostAddress(host_addr, &key)) {
    // Unknown host target -> this function is not safely cacheable.
    failed_ = true;
    return;
  }
  relocs_.push_back(
      {code_offset, kind, width, addend, InternSymbol(key)});
}

// ---- X64AOTCache ----

X64AOTCache::X64AOTCache(X64Backend* backend, X64CodeCache* code_cache)
    : backend_(backend), code_cache_(code_cache), recorder_(&symbols_) {}

X64AOTCache::~X64AOTCache() { FlushAll(); }

uint64_t X64AOTCache::ABIHash() {
  // Bump this literal whenever the emitter, sequences, or X64BackendContext
  // change in a way that invalidates cached native code.
  uint64_t hash = 0x0000000000010002ull;
  hash ^= static_cast<uint64_t>(sizeof(X64BackendContext));
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
  s.RegisterHostAddress("thunk.host_to_guest",
                        reinterpret_cast<void*>(backend_->host_to_guest_thunk()));
  s.RegisterHostAddress("thunk.guest_to_host",
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
      reinterpret_cast<void*>(backend_->synchronize_guest_and_host_stack_helper()));
  s.RegisterHostAddress(
      "helper.sync_stack_8",
      reinterpret_cast<void*>(backend_->synchronize_guest_and_host_stack_helper_for_size(1)));
  s.RegisterHostAddress(
      "helper.sync_stack_16",
      reinterpret_cast<void*>(backend_->synchronize_guest_and_host_stack_helper_for_size(2)));
  s.RegisterHostAddress(
      "helper.sync_stack_32",
      reinterpret_cast<void*>(backend_->synchronize_guest_and_host_stack_helper_for_size(4)));
  s.RegisterHostAddress("data.emitter",
                        reinterpret_cast<void*>(backend_->emitter_data()));

  enabled_ = true;
  XELOGCPU("AOT: Cache initialized at {}", cache_root_.string());
  return true;
}

void X64AOTCache::OnFunctionCompiled(uint32_t guest_address,
                                     const void* machine_code,
                                     const EmitFunctionInfo& info,
                                     uint64_t guest_code_hash,
                                     uintptr_t module_key) {
  if (!enabled_) {
    return;
  }

  auto global_lock = global_critical_region_.Acquire();

  if (!recorder_.active() || recorder_.failed()) {
    return;
  }

  auto bf = std::make_unique<BufferedFunction>();
  bf->guest_address = guest_address;
  bf->guest_code_hash = guest_code_hash;
  size_t total_size = info.code_size.total;
  bf->code_blob.assign(static_cast<const uint8_t*>(machine_code),
                       static_cast<const uint8_t*>(machine_code) + total_size);
  bf->emit_info = info;
  bf->relocs = recorder_.relocs();
  bf->symtab = recorder_.symbol_table();

  pending_[module_key].push_back(std::move(bf));
}

bool X64AOTCache::ApplyRelocs(uint8_t* code,
                              const std::vector<AOTReloc>& relocs,
                              const std::vector<std::string>& symtab) {
  for (const auto& r : relocs) {
    if (r.symbol_id >= symtab.size()) {
      XELOGE("AOT: Reloc symbol_id {} out of range", r.symbol_id);
      return false;
    }
    void* host = symbols_.HostAddressForKey(symtab[r.symbol_id]);
    if (!host) {
      XELOGE("AOT: Symbol '{}' not found in registry", symtab[r.symbol_id]);
      return false;
    }
    uint64_t value =
        reinterpret_cast<uint64_t>(host) + static_cast<uint64_t>(r.addend);
    if (r.width == 8) {
      std::memcpy(code + r.offset, &value, sizeof(uint64_t));
    } else if (r.width == 4) {
      uint32_t v32 = static_cast<uint32_t>(value);
      std::memcpy(code + r.offset, &v32, sizeof(uint32_t));
    } else {
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

// Write buffered functions to disk for one module, then clear the buffer.
void X64AOTCache::FlushModule(
    uint32_t title_id, const uint8_t module_hash[20],
    std::vector<std::unique_ptr<BufferedFunction>>&& functions) {
  if (functions.empty()) {
    return;
  }

  auto path = ModuleCachePath(cache_root_, module_hash);
  std::error_code ec;
  std::filesystem::create_directories(path.parent_path(), ec);

  FILE* f = xe::filesystem::OpenFile(path, "wb");
  if (!f) {
    XELOGE("AOT: Cannot write cache file {}", path.string());
    return;
  }

  AOTFileHeader header = {};
  header.magic = kMagic;
  header.version = kVersion;
  header.abi_hash = ABIHash();
  header.title_id = title_id;
  std::memcpy(header.module_hash, module_hash, 20);
  header.func_count = static_cast<uint32_t>(functions.size());

  if (fwrite(&header, sizeof(header), 1, f) != 1) {
    fclose(f);
    XELOGE("AOT: Failed to write header to {}", path.string());
    return;
  }

  size_t written = 0;
  for (const auto& fn : functions) {
    AOTFuncHeader fh = {};
    fh.guest_address = fn->guest_address;
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
      XELOGE("AOT: Failed to write func header at {}", path.string());
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
      XELOGE("AOT: Failed to write code blob at {}", path.string());
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
    if (symtab_size &&
        fwrite(symtab_data.data(), symtab_size, 1, f) != 1) {
      fclose(f);
      return;
    }

    ++written;
  }

  fclose(f);
  XELOGCPU("AOT: Flushed {} functions to {}", written, path.string());
}

void X64AOTCache::FlushAll() {
  auto global_lock = global_critical_region_.Acquire();

  if (pending_.empty()) {
    return;
  }

  XELOGCPU("AOT: Flushing {} modules to disk", pending_.size());
  // We don't have title_id/module_hash for pending buffers without a
  // PreloadModule call. In normal operation, PreloadModule is called which
  // flushes the buffer. This is a fallback for shutdown.
  pending_.clear();
}

size_t X64AOTCache::PreloadModule(Module* module, uint32_t title_id,
                                  const uint8_t module_hash[20],
                                  ProgressCallback progress) {
  if (!enabled_) {
    return 0;
  }

  // First, flush any pending (JIT-compiled) functions for this module to disk.
  {
    auto global_lock = global_critical_region_.Acquire();
    uintptr_t module_key = reinterpret_cast<uintptr_t>(module);
    auto it = pending_.find(module_key);
    if (it != pending_.end() && !it->second.empty()) {
      FlushModule(title_id, module_hash, std::move(it->second));
      pending_.erase(it);
    }
  }

  // Now read the cache file and preload.
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
    if (fh.code_size &&
        fread(code_blob.data(), fh.code_size, 1, f) != 1) {
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
        symtab.push_back(start);
        pos += len + 1;
      }
    }

    // Validate PPC bytes against cached hash.
    uint32_t guest_code_size = 0;
    if (module->ContainsAddress(fh.guest_address)) {
      auto* symbol = module->LookupSymbol(fh.guest_address, false);
      if (symbol && symbol->is_guest()) {
        auto* gf = static_cast<GuestFunction*>(symbol);
        guest_code_size = gf->has_end_address()
                              ? gf->end_address() - fh.guest_address
                              : 0;
      }
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

    // Place code into the cache (copies bytes, updates indirection table).
    void* exec = nullptr;
    void* write = nullptr;
    code_cache_->PlaceGuestCode(fh.guest_address, code_blob.data(), emit_info,
                                gf, exec, write);

    // Apply relocations in the writable view.
    if (!ApplyRelocs(reinterpret_cast<uint8_t*>(write), relocs, symtab)) {
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
