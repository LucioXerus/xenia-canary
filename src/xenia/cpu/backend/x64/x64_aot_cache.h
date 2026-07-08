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
}  // namespace cpu

namespace cpu {
namespace backend {
namespace x64 {

class X64Backend;
class X64CodeCache;

enum class AOTRelocKind : uint16_t {
  kNone = 0,
  kBackendHelper = 1,    // absolute imm64 to an X64Backend helper/thunk
  kNativeFunction = 2,   // absolute imm64 to a registered native handler
  kEmitterData = 3,      // ref to emitter_data() base + addend
  kBuiltinHandler = 4,   // absolute imm64 to a builtin function handler
  kBuiltinArg0 = 5,      // absolute imm64 to a builtin function arg0
  kBuiltinArg1 = 6,      // absolute imm64 to a builtin function arg1
};

struct AOTReloc {
  uint32_t offset;      // byte offset within the function's code blob
  AOTRelocKind kind;
  uint16_t width;       // 4 or 8
  int64_t addend;
  uint32_t symbol_id;   // index into the module's symbol string table
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

// Per-compile recorder handed to the emitter to note relocation sites.
class AOTRecorder {
 public:
  explicit AOTRecorder(AOTSymbolRegistry* symbols) : symbols_(symbols) {}
  bool active() const { return active_; }
  void Begin() { active_ = true; relocs_.clear(); symbol_table_.clear();
                  symbol_index_.clear(); failed_ = false; }
  void Abort() { failed_ = true; }  // marks fn as non-cacheable
  bool failed() const { return failed_; }

  void RecordHostPtr(uint32_t code_offset, void* host_addr,
                     AOTRelocKind kind, uint16_t width, int64_t addend = 0);

  const std::vector<AOTReloc>& relocs() const { return relocs_; }
  const std::vector<std::string>& symbol_table() const { return symbol_table_; }

 private:
  uint32_t InternSymbol(const std::string& key);
  AOTSymbolRegistry* symbols_;
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
  AOTRecorder* recorder() { return &recorder_; }

  bool enabled() const { return enabled_; }
  void set_enabled(bool v) { enabled_ = v; }

  // Called after a JIT compile succeeds: buffers the function for disk write.
  // module_key is an opaque identifier for the guest module (module pointer).
  void OnFunctionCompiled(uint32_t guest_address, const void* machine_code,
                          const EmitFunctionInfo& info,
                          uint64_t guest_code_hash,
                          uintptr_t module_key);

  // Flush all pending functions for the given module to disk, then preload.
  // Title launch path: call this before running guest code.
  size_t PreloadModule(Module* module, uint32_t title_id,
                       const uint8_t module_hash[20],
                       ProgressCallback progress);

  // Flush all pending buffers to disk (e.g. on shutdown).
  void FlushAll();

  static uint64_t ABIHash();  // bump-on-change guard

 private:
  struct BufferedFunction;
  struct BufferedModule;

  bool ApplyRelocs(uint8_t* code, const std::vector<AOTReloc>& relocs,
                   const std::vector<std::string>& symtab);

  void FlushModule(uint32_t title_id, const uint8_t module_hash[20],
                   std::vector<std::unique_ptr<BufferedFunction>>&& functions);

  X64Backend* backend_;
  X64CodeCache* code_cache_;
  AOTSymbolRegistry symbols_;
  AOTRecorder recorder_;
  std::filesystem::path cache_root_;
  bool enabled_ = false;
  xe::global_critical_region global_critical_region_;
  // Pending functions awaiting disk flush, keyed by module pointer.
  std::unordered_map<uintptr_t, std::vector<std::unique_ptr<BufferedFunction>>>
      pending_;
};

}  // namespace x64
}  // namespace backend
}  // namespace cpu
}  // namespace xe

#endif  // XENIA_CPU_BACKEND_X64_X64_AOT_CACHE_H_
