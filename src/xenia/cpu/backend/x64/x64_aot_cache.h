/**
 ******************************************************************************
 * Xenia : Xbox 360 Emulator Research Project                                 *
 ******************************************************************************
 * Copyright 2026 Ben Vanik. All rights reserved.                             *
 * Released under the BSD license - see LICENSE in the root for more details. *
 ******************************************************************************
 */

#ifndef XENIA_CPU_BACKEND_X64_X64_AOT_CACHE_H_
#define XENIA_CPU_BACKEND_X64_X64_AOT_CACHE_H_

#include <cstdint>
#include <cstring>
#include <filesystem>
#include <functional>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include "xenia/base/mutex.h"
#include "xenia/cpu/backend/code_cache_base.h"

namespace xe {
namespace cpu {
class GuestFunction;
class Module;
class Processor;
}  // namespace cpu

namespace cpu {
namespace backend {
namespace x64 {

class X64Backend;
class X64CodeCache;

enum class AOTRelocKind : uint16_t {
  kNone = 0,
  // Absolute imm64 host pointer (width 8): a registered host symbol such as a
  // backend helper/thunk, builtin handler/arg, native/extern handler, or the
  // resolve-function helper. Value = symbol_addr + addend.
  kAbs64HostPtr = 1,
  // disp32 absolute memory ref into the fixed-VA emitter data region
  // (width 4): XMM/const data accessed via ptr[emitter_data + off].
  // Value = symbol_addr + addend (truncated to 32 bits).
  kAbsData32 = 2,
  // rel32 call/jmp to a registered host symbol (width 4): E8/E9 disp.
  // On load: disp = (symbol_now + addend) - (exec_base + reloc_offset + 4).
  kRel32HostCall = 3,
};

struct AOTReloc {
  uint32_t offset;  // byte offset within the function's code blob
  AOTRelocKind kind;
  uint16_t width;  // 4 or 8
  int64_t addend;
  uint32_t symbol_id;  // index into the function's symbol string table
};

// Maps host addresses <-> stable string keys so we can rebind them next run.
class AOTSymbolRegistry {
 public:
  void RegisterHostAddress(const std::string& key, void* host_addr);
  bool KeyForHostAddress(void* host_addr, std::string* out_key) const;
  void* HostAddressForKey(const std::string& key) const;

 private:
  std::unordered_map<uintptr_t, std::string> addr_to_key_;
  std::unordered_map<std::string, void*> key_to_addr_;
};

// Per-compile recorder owned by each X64Emitter (NOT shared across threads).
// The emitter Begin()s it before codegen, records every host-pointer/rel32
// bake site, then the AOT cache copies out the relocs+symtab under a lock at
// capture time and resets it.
class AOTRecorder {
 public:
  AOTRecorder() = default;
  void set_symbols(AOTSymbolRegistry* symbols) { symbols_ = symbols; }

  bool active() const { return active_; }
  bool failed() const { return failed_; }

  void Begin();
  void Reset();  // clears all per-function state (called after capture)

  // Records an absolute imm64 host pointer. `end_offset` is the emitter size
  // AFTER the `mov reg, imm` instruction has been emitted (i.e. getSize()).
  // The immediate is always the last field of the instruction, so the imm
  // starts at (end_offset - width); this is robust to REX prefixes on
  // extended registers (r8-r15) which the older "+2/-1" heuristic got wrong,
  // causing ApplyRelocs to overwrite the opcode byte on reload (black screen).
  void RecordHostPtr(uint32_t end_offset, void* host_addr, int64_t addend = 0);
  // Records a disp32 absolute memory ref into the fixed emitter-data region
  // (width 4). host_addr is the emitter-data base (or sub-base); addend is
  // the byte offset within it.
  void RecordAbsData32(uint32_t code_offset, void* host_addr,
                       int64_t addend = 0);
  // Records a rel32 call/jmp to a host symbol (E8/E9; width 4). The recorder
  // stores the symbol + instr offset; the load path recomputes the disp.
  void RecordRel32HostCall(uint32_t code_offset, void* host_addr,
                           int64_t addend = 0);

  // Marks the current function as non-cacheable (e.g. a dynamic pointer was
  // baked that cannot be relocated).
  void Abort() { failed_ = true; }

  const std::vector<AOTReloc>& relocs() const { return relocs_; }
  const std::vector<std::string>& symbol_table() const { return symbol_table_; }

  // Takes ownership of the recorded relocs/symtab (moves them out). The
  // recorder is left in a Reset() state.
  void TakeData(std::vector<AOTReloc>* out_relocs,
                std::vector<std::string>* out_symtab);

 private:
  uint32_t InternSymbol(const std::string& key);
  void RecordInternal(uint32_t code_offset, void* host_addr, AOTRelocKind kind,
                      uint16_t width, int64_t addend);

  AOTSymbolRegistry* symbols_ = nullptr;
  std::vector<AOTReloc> relocs_;
  std::vector<std::string> symbol_table_;
  std::unordered_map<std::string, uint32_t> symbol_index_;
  bool active_ = false;
  bool failed_ = false;
};

class X64AOTCache {
 public:
  using ProgressCallback =
      std::function<void(size_t done, size_t total, const std::string& label)>;

  X64AOTCache(X64Backend* backend, X64CodeCache* code_cache);
  ~X64AOTCache();

  bool Initialize(const std::filesystem::path& cache_root);
  AOTSymbolRegistry& symbols() { return symbols_; }

  // Registers the process's builtin/extern kernel-export handlers in the
  // symbol registry under STABLE keys (builtin name; export name+ordinal), so
  // that (a) the recorder can find a key for these host pointers during
  // capture and (b) ApplyRelocs can rebind them to the current (ASLR'd)
  // addresses on the next launch. Must be called at launch (before gameplay
  // JIT begins and before PreloadModule applies relocations) in BOTH the
  // capture session and the reload session. Idempotent.
  void RegisterDynamicSymbols(Processor* processor);

  bool enabled() const { return enabled_; }
  void set_enabled(bool v) { enabled_ = v; }

  // Called from X64Emitter::Emplace AFTER ready() (so the bytes at
  // machine_code are the final, relocated, placed bytes). The recorder must
  // hold this compile's relocation data. module_key is the guest module
  // pointer. title_id/module_hash are attached to the buffer so FlushAll can
  // write to disk without a live Module* at shutdown.
  void CaptureFunction(uint32_t guest_address, uint32_t guest_code_size,
                       const void* machine_code, const EmitFunctionInfo& info,
                       uint64_t guest_code_hash, uintptr_t module_key,
                       uint32_t title_id, const uint8_t module_hash[20],
                       AOTRecorder* recorder);

  // Reads the cache file for this module (if present) and preloads functions.
  // Called at title launch. Does NOT flush pending (those are written at
  // shutdown/title-teardown via FlushModuleForTeardown).
  size_t PreloadModule(Module* module, uint32_t title_id,
                       const uint8_t module_hash[20],
                       ProgressCallback progress);

  // Writes all pending buffered functions for the given module to disk, then
  // clears them. Called at title-teardown/shutdown when the Module is still
  // alive so we have the hash.
  void FlushModuleForTeardown(uint32_t title_id, const uint8_t module_hash[20],
                              uintptr_t module_key);

  // Writes ALL pending buffers to disk (fallback shutdown path). Buffers that
  // lack a module_hash are discarded (cannot be keyed).
  void FlushAll();

  static uint64_t ABIHash();  // bump-on-change guard

 private:
  struct BufferedFunction;
  struct BufferedModule;

  bool ApplyRelocs(uint8_t* write_base, uintptr_t exec_base, size_t code_size,
                   const std::vector<AOTReloc>& relocs,
                   const std::vector<std::string>& symtab);

  void FlushModule(uint32_t title_id, const uint8_t module_hash[20],
                   std::vector<std::unique_ptr<BufferedFunction>>&& functions);

  X64Backend* backend_;
  X64CodeCache* code_cache_;
  AOTSymbolRegistry symbols_;
  std::filesystem::path cache_root_;
  bool enabled_ = false;
  xe::global_critical_region global_critical_region_;
  // Pending functions awaiting disk flush, keyed by module pointer.
  std::unordered_map<uintptr_t, std::unique_ptr<BufferedModule>> pending_;
};

}  // namespace x64
}  // namespace backend
}  // namespace cpu
}  // namespace xe

#endif  // XENIA_CPU_BACKEND_X64_X64_AOT_CACHE_H_
