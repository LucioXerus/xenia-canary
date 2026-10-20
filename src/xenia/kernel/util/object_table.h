/**
 ******************************************************************************
 * Xenia : Xbox 360 Emulator Research Project                                 *
 ******************************************************************************
 * Copyright 2020 Ben Vanik. All rights reserved.                             *
 * Released under the BSD license - see LICENSE in the root for more details. *
 ******************************************************************************
 */

#ifndef XENIA_KERNEL_UTIL_OBJECT_TABLE_H_
#define XENIA_KERNEL_UTIL_OBJECT_TABLE_H_

#include <atomic>
#include <functional>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include "xenia/base/mutex.h"
#include "xenia/base/string_key.h"
#include "xenia/kernel/xobject.h"
#include "xenia/xbox.h"

namespace xe {
class ByteStream;
}  // namespace xe

namespace xe {
namespace kernel {
namespace util {

class ObjectTable {
 public:
  ObjectTable();
  ~ObjectTable();

  void Reset();

  X_STATUS AddHandle(XObject* object, X_HANDLE* out_handle);
  X_STATUS DuplicateHandle(X_HANDLE orig, X_HANDLE* out_handle);
  X_STATUS RetainHandle(X_HANDLE handle);
  X_STATUS ReleaseHandle(X_HANDLE handle);
  X_STATUS ReleaseHandleInLock(X_HANDLE handle);
  X_STATUS RemoveHandle(X_HANDLE handle);

  bool Save(ByteStream* stream);
  bool Restore(ByteStream* stream);

  // Restores a XObject reference with a handle. Mainly for internal use - do
  // not use.
  X_STATUS RestoreHandle(X_HANDLE handle, XObject* object);
  template <typename T>
  object_ref<T> LookupObject(X_HANDLE handle, bool already_locked = false) {
    auto object = LookupObject(handle, already_locked);
    if (object) {
      if (object->type() != T::kObjectType) {
        object->Release();
        return object_ref<T>();
      }
    }
    auto result = object_ref<T>(reinterpret_cast<T*>(object));
    return result;
  }

  X_STATUS AddNameMapping(const std::string_view name, X_HANDLE handle);
  void RemoveNameMapping(const std::string_view name);
  X_STATUS GetObjectByName(const std::string_view name, X_HANDLE* out_handle);
  template <typename T>
  std::vector<object_ref<T>> GetObjectsByType(XObject::Type type) {
    std::vector<object_ref<T>> results;
    GetObjectsByType(
        type, reinterpret_cast<std::vector<object_ref<XObject>>*>(&results));
    return results;
  }

  template <typename T>
  std::vector<object_ref<T>> GetObjectsByType() {
    std::vector<object_ref<T>> results;
    GetObjectsByType(
        T::kObjectType,
        reinterpret_cast<std::vector<object_ref<XObject>>*>(&results));
    return results;
  }

  std::vector<object_ref<XObject>> GetAllObjects();
  void PurgeAllObjects();  // Purges the object table of all guest objects

  // Number of independent reader shards. LookupObject() announces itself in
  // one of them, so concurrent lookups on different threads do not bounce the
  // same cache line; only a retirement scans them all. Must be a power of two.
  static constexpr uint32_t kReaderShardCount = 64;

 private:
  struct ObjectTableEntry {
    int handle_ref_count = 0;
    // Accessed atomically (__atomic_* on this address) in the lock-free
    // LookupObject() path; ordinary accesses below happen under the global
    // critical region, except for read-only ones that are never concurrent
    // with a change to the same entry.
    XObject* object = nullptr;
  };
  struct ReaderShard {
    // Number of threads between announcing a lookup and finishing it.
    // Incremented and decremented by the same thread, so threads that hash to
    // the same shard add up instead of overwriting each other; that makes the
    // choice of shard a pure performance question rather than a correctness
    // one.
    std::atomic<uint32_t> active{0};
    char padding[64 - sizeof(std::atomic<uint32_t>)];
  };
  // A reference to an object whose table reference was dropped, held until no
  // lookup can still be about to retain it.
  struct RetiredObject {
    RetiredObject* next;
    XObject* object;
  };

  // Announces a lookup to DropTableReference(). The fences are
  // what make the hand-over sound: the reader publishes, fences, then loads
  // the entry, while the table empties the entry, fences, then scans the
  // shards. The two fences are totally ordered, so either the table sees this
  // reader and defers the release, or this reader observes an already-empty
  // entry. Without them the announcement could be reordered after the load.
  static void BeginLookup(ReaderShard* shard) {
    shard->active.fetch_add(1, std::memory_order_relaxed);
    std::atomic_thread_fence(std::memory_order_seq_cst);
  }
  static void EndLookup(ReaderShard* shard) {
    shard->active.fetch_sub(1, std::memory_order_release);
  }
  // Whether any lookup is between BeginLookup() and EndLookup() right now.
  static bool AnyReaderActive();

  void RetireArray(ObjectTableEntry* array);
  ObjectTableEntry* LookupTableInLock(X_HANDLE handle);
  ObjectTableEntry* LookupTable(X_HANDLE handle);
  XObject* LookupObject(X_HANDLE handle, bool already_locked);
  void GetObjectsByType(XObject::Type type,
                        std::vector<object_ref<XObject>>* results);

  // Drops the reference this table holds on `object`, which has just been
  // cleared from its entry. The reference is not released right away when a
  // lookup may be about to retain the object; it is parked and released once
  // no lookup is in flight. Must be called with the global critical region
  // held.
  void DropTableReference(XObject* object);
  // Releases every parked reference. Must be called with the global critical
  // region held.
  void ReclaimRetired();

  X_HANDLE TranslateHandle(X_HANDLE handle);
  static constexpr uint32_t GetHandleSlot(X_HANDLE handle, bool host) {
    handle &= host ? ~XObject::kHandleHostBase : ~XObject::kHandleBase;
    return handle >> 2;
  }
  X_STATUS FindFreeSlot(uint32_t* out_slot, bool host);
  bool Resize(uint32_t new_capacity, bool host);

  xe::global_critical_region global_critical_region_;
  // Written under the global critical region only. Reads of handle entries in
  // LookupObject() are lock-free, hence the atomics (see the publishing
  // protocol documented there and in Resize()).
  uint32_t table_capacity_ = 0;
  uint32_t host_table_capacity_ = 0;
  ObjectTableEntry* table_ = nullptr;
  ObjectTableEntry* host_table_ = nullptr;
  uint32_t last_free_entry_ = 0;
  uint32_t last_free_host_entry_ = 0;
  std::unordered_map<string_key_case, X_HANDLE> name_table_;

  // References parked until the lookups in flight when they were dropped have
  // finished. Only touched with the global critical region held.
  RetiredObject* retired_ = nullptr;

  // Reader shards, shared by every table: a lookup announces itself before it
  // knows which table it will touch, and a retirement has to wait out any
  // lookup regardless of which table it is reading.
  static ReaderShard shards_[kReaderShardCount];
};

// Generic lookup
template <>
object_ref<XObject> ObjectTable::LookupObject<XObject>(X_HANDLE handle,
                                                       bool already_locked);

}  // namespace util
}  // namespace kernel
}  // namespace xe

#endif  // XENIA_KERNEL_UTIL_OBJECT_TABLE_H_
