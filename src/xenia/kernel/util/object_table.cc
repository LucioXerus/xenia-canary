/**
 ******************************************************************************
 * Xenia : Xbox 360 Emulator Research Project                                 *
 ******************************************************************************
 * Copyright 2020 Ben Vanik. All rights reserved.                             *
 * Released under the BSD license - see LICENSE in the root for more details. *
 ******************************************************************************
 */

#include "xenia/kernel/util/object_table.h"

#include "xenia/base/byte_stream.h"
#include "xenia/base/logging.h"
#include "xenia/kernel/xobject.h"
#include "xenia/kernel/xthread.h"

namespace xe {
namespace kernel {
namespace util {

ObjectTable::ObjectTable() {}

ObjectTable::~ObjectTable() { Reset(); }

void ObjectTable::Reset() {
  auto global_lock = global_critical_region_.Acquire();

  // Release all objects, clearing their handles first so destructors
  // don't assert on non-empty handles_.
  for (uint32_t n = 0; n < table_capacity_; n++) {
    ObjectTableEntry& entry = table_[n];
    if (entry.object) {
      entry.object->handles().clear();
      entry.handle_ref_count = 0;
      entry.object->Release();
    }
    __atomic_store_n(&entry.object, nullptr, __ATOMIC_RELEASE);
  }
  for (uint32_t n = 0; n < host_table_capacity_; n++) {
    ObjectTableEntry& entry = host_table_[n];
    if (entry.object) {
      entry.object->handles().clear();
      entry.handle_ref_count = 0;
      entry.object->Release();
    }
    __atomic_store_n(&entry.object, nullptr, __ATOMIC_RELEASE);
  }

  // Lookups are lock-free, so a thread may still be indexing the old array
  // after it has been cleared: retire rather than free, then publish null so
  // no new lookup can reach those arrays.
  RetireArray(table_);
  RetireArray(host_table_);
  __atomic_store_n(&table_, static_cast<ObjectTableEntry*>(nullptr),
                   __ATOMIC_RELEASE);
  __atomic_store_n(&host_table_, static_cast<ObjectTableEntry*>(nullptr),
                   __ATOMIC_RELEASE);
  // Publish the zero capacities with release as well: lookups pair these with
  // acquire loads, and a reader that observed a nonzero capacity but a null
  // array must not index it (both LookupObject() branches guard against null).
  __atomic_store_n(&table_capacity_, 0u, __ATOMIC_RELEASE);
  __atomic_store_n(&host_table_capacity_, 0u, __ATOMIC_RELEASE);
  last_free_entry_ = 0;
  last_free_host_entry_ = 0;
}

// Retires an array replaced by Resize() or Reset().
void ObjectTable::RetireArray(ObjectTableEntry* array) {
  // Lock-free lookups make it impossible to free a replaced array at a safe
  // point: a reader that loaded it may still be in the middle of a lookup on
  // another thread, so neither immediate free nor reuse is safe. Growth is
  // geometric and the tables are small (an entry is 16 bytes), so the total
  // retired memory is at most twice the table size ever reached and only
  // happens on the handful of rare resizes.
  (void)array;
}

bool ObjectTable::Resize(uint32_t new_capacity, bool host) {
  const uint32_t capacity = host ? host_table_capacity_ : table_capacity_;
  const size_t new_size = new_capacity * sizeof(ObjectTableEntry);
  const size_t old_size = capacity * sizeof(ObjectTableEntry);
  // Never realloc(): a lock-free LookupObject() may be reading the old array
  // while the table is being grown. Instead build a new array, publish it with
  // a release store, and retire the old one so readers that already loaded the
  // old pointer can finish their lookup safely.
  auto new_table = reinterpret_cast<ObjectTableEntry*>(malloc(new_size));
  if (!new_table) {
    return false;
  }
  if (capacity) {
    std::memcpy(new_table, host ? host_table_ : table_, old_size);
  }
  std::memset(reinterpret_cast<uint8_t*>(new_table) + old_size, 0,
              new_size - old_size);

  // Publish the new pointer and capacity in that order (release) so lock-free
  // handle lookups never observe a capacity that is larger than the table they
  // are indexing into.
  if (host) {
    last_free_host_entry_ = capacity;
    __atomic_store_n(&host_table_, new_table, __ATOMIC_RELEASE);
    __atomic_store_n(&host_table_capacity_, new_capacity, __ATOMIC_RELEASE);
  } else {
    last_free_entry_ = capacity;
    __atomic_store_n(&table_, new_table, __ATOMIC_RELEASE);
    __atomic_store_n(&table_capacity_, new_capacity, __ATOMIC_RELEASE);
  }

  // The array is deliberately not freed (see RetireArray).
  return true;
}

X_STATUS ObjectTable::FindFreeSlot(uint32_t* out_slot, bool host) {
  // Find a free slot.
  uint32_t slot = host ? last_free_host_entry_ : last_free_entry_;
  uint32_t capacity = host ? host_table_capacity_ : table_capacity_;
  uint32_t scan_count = 0;
  while (scan_count < capacity) {
    ObjectTableEntry& entry = host ? host_table_[slot] : table_[slot];
    if (!entry.object) {
      *out_slot = slot;
      return X_STATUS_SUCCESS;
    }
    scan_count++;
    slot = (slot + 1) % capacity;
    if (slot == 0 && host) {
      // Never allow 0 handles.
      scan_count++;
      slot++;
    }
  }

  // Table out of slots, expand.
  uint32_t new_table_capacity = std::max(16 * 1024u, capacity * 2);
  if (!Resize(new_table_capacity, host)) {
    return X_STATUS_NO_MEMORY;
  }

  // Never allow 0 handles on host.
  slot = host ? ++last_free_host_entry_ : last_free_entry_++;
  *out_slot = slot;

  return X_STATUS_SUCCESS;
}

X_STATUS ObjectTable::AddHandle(XObject* object, X_HANDLE* out_handle) {
  X_STATUS result = X_STATUS_SUCCESS;

  uint32_t handle = 0;
  {
    auto global_lock = global_critical_region_.Acquire();

    // Find a free slot.
    uint32_t slot = 0;
    bool host_object = object->is_host_object();
    result = FindFreeSlot(&slot, host_object);

    // Stash.
    if (XSUCCEEDED(result)) {
      ObjectTableEntry& entry = host_object ? host_table_[slot] : table_[slot];
      __atomic_store_n(&entry.object, object, __ATOMIC_RELEASE);
      entry.handle_ref_count = 1;
      handle = slot << 2;
      if (!host_object) {
        if (object->type() != XObject::Type::Socket) {
          handle += XObject::kHandleBase;
        }
      } else {
        handle += XObject::kHandleHostBase;
      }
      object->handles().push_back(handle);

      // Retain so long as the object is in the table.
      object->Retain();

      XELOGD("Added handle:{:08X} for {}", handle, typeid(*object).name());
    }
  }

  if (XSUCCEEDED(result)) {
    if (out_handle) {
      *out_handle = handle;
    }
  }

  return result;
}

X_STATUS ObjectTable::DuplicateHandle(X_HANDLE handle, X_HANDLE* out_handle) {
  X_STATUS result = X_STATUS_SUCCESS;
  handle = TranslateHandle(handle);

  XObject* object = LookupObject(handle, false);
  if (object) {
    result = AddHandle(object, out_handle);
    object->Release();  // Release the ref that LookupObject took
  } else {
    result = X_STATUS_INVALID_HANDLE;
  }

  return result;
}

X_STATUS ObjectTable::RetainHandle(X_HANDLE handle) {
  auto global_lock = global_critical_region_.Acquire();

  ObjectTableEntry* entry = LookupTableInLock(handle);
  if (!entry) {
    return X_STATUS_INVALID_HANDLE;
  }

  entry->handle_ref_count++;
  return X_STATUS_SUCCESS;
}

X_STATUS ObjectTable::ReleaseHandle(X_HANDLE handle) {
  auto global_lock = global_critical_region_.Acquire();

  return ReleaseHandleInLock(handle);
}
X_STATUS ObjectTable::ReleaseHandleInLock(X_HANDLE handle) {
  ObjectTableEntry* entry = LookupTableInLock(handle);
  if (!entry) {
    return X_STATUS_INVALID_HANDLE;
  }

  if (--entry->handle_ref_count == 0) {
    // No more references. Remove it from the table.
    return RemoveHandle(handle);
  }

  // FIXME: Return a status code telling the caller it wasn't released
  // (but not a failure code)
  return X_STATUS_SUCCESS;
}
X_STATUS ObjectTable::RemoveHandle(X_HANDLE handle) {
  X_STATUS result = X_STATUS_SUCCESS;

  handle = TranslateHandle(handle);
  if (!handle) {
    return X_STATUS_INVALID_HANDLE;
  }
  auto global_lock = global_critical_region_.Acquire();

  ObjectTableEntry* entry = LookupTableInLock(handle);
  if (!entry) {
    return X_STATUS_INVALID_HANDLE;
  }

  if (entry->object) {
    auto object = entry->object;
    // Release store: LookupObject() reads the field lock-free, and on a
    // weakly-ordered target the clearing of the pointer must be published
    // before the object can be destroyed by the Release() below.
    __atomic_store_n(&entry->object, static_cast<XObject*>(nullptr),
                     __ATOMIC_RELEASE);
    assert_zero(entry->handle_ref_count);
    entry->handle_ref_count = 0;

    // Walk the object's handles and remove this one.
    auto handle_entry = std::ranges::find(object->handles(), handle);
    if (handle_entry != object->handles().end()) {
      object->handles().erase(handle_entry);
    }

    XELOGD("Removed handle:{:08X} for {}", handle, typeid(*object).name());

    // Remove object name from mapping to prevent naming collision.
    if (!object->name().empty()) {
      RemoveNameMapping(object->name());
    }
    // Release now that the object has been removed from the table.
    object->Release();
  }

  return X_STATUS_SUCCESS;
}

std::vector<object_ref<XObject>> ObjectTable::GetAllObjects() {
  auto lock = global_critical_region_.Acquire();
  std::vector<object_ref<XObject>> results;

  for (uint32_t slot = 0; slot < host_table_capacity_; slot++) {
    auto& entry = host_table_[slot];
    if (entry.object && std::find(results.begin(), results.end(),
                                  entry.object) == results.end()) {
      entry.object->Retain();
      results.push_back(object_ref<XObject>(entry.object));
    }
  }
  for (uint32_t slot = 0; slot < table_capacity_; slot++) {
    auto& entry = table_[slot];
    if (entry.object && std::find(results.begin(), results.end(),
                                  entry.object) == results.end()) {
      entry.object->Retain();
      results.push_back(object_ref<XObject>(entry.object));
    }
  }

  return results;
}

void ObjectTable::PurgeAllObjects() {
  auto lock = global_critical_region_.Acquire();
  for (uint32_t slot = 0; slot < table_capacity_; slot++) {
    auto& entry = table_[slot];
    if (entry.object) {
      entry.handle_ref_count = 0;
      entry.object->ReleaseHandle();

      __atomic_store_n(&entry.object, nullptr, __ATOMIC_RELEASE);
    }
  }
}

ObjectTable::ObjectTableEntry* ObjectTable::LookupTable(X_HANDLE handle) {
  auto global_lock = global_critical_region_.Acquire();
  return LookupTableInLock(handle);
}

ObjectTable::ObjectTableEntry* ObjectTable::LookupTableInLock(X_HANDLE handle) {
  handle = TranslateHandle(handle);
  if (!handle) {
    return nullptr;
  }

  const bool is_host_object = XObject::is_handle_host_object(handle);
  uint32_t slot = GetHandleSlot(handle, is_host_object);
  if (is_host_object) {
    if (slot <= host_table_capacity_) {
      return &host_table_[slot];
    }
  } else if (slot <= table_capacity_) {
    return &table_[slot];
  }

  return nullptr;
}

// Generic lookup
template <>
object_ref<XObject> ObjectTable::LookupObject<XObject>(X_HANDLE handle,
                                                       bool already_locked) {
  auto object = ObjectTable::LookupObject(handle, already_locked);
  auto result = object_ref<XObject>(reinterpret_cast<XObject*>(object));
  return result;
}

XObject* ObjectTable::LookupObject(X_HANDLE handle, bool already_locked) {
  handle = TranslateHandle(handle);
  if (!handle) {
    return nullptr;
  }

  const bool is_host_object = XObject::is_handle_host_object(handle);
  uint32_t slot = GetHandleSlot(handle, is_host_object);
  // Publish/consume protocol with Resize(): the new table is stored with
  // release, then the (larger) capacity with release; readers acquire-load the
  // capacity first and only then the table, so a capacity that covers the slot
  // always comes with a table that covers it.
  ObjectTableEntry* entries;
  uint32_t capacity;
  XObject* object;
  if (is_host_object) {
    capacity = __atomic_load_n(&host_table_capacity_, __ATOMIC_ACQUIRE);
    if (slot >= capacity) {
      return nullptr;
    }
    entries = __atomic_load_n(&host_table_, __ATOMIC_ACQUIRE);
    if (!entries) {
      return nullptr;
    }
  } else {
    capacity = __atomic_load_n(&table_capacity_, __ATOMIC_ACQUIRE);
    if (slot >= capacity) {
      return nullptr;
    }
    entries = __atomic_load_n(&table_, __ATOMIC_ACQUIRE);
    if (!entries) {
      return nullptr;
    }
  }

  // Handle lookups are the single hottest kernel operation (every wait, read,
  // write and signal is addressed by handle), so this is a lock-free lookup:
  // take a pointer reference on the target before touching it, then check that
  // the entry still refers to that object.
  //
  // This is only safe because an entry's object pointer is never replaced
  // while it is non-null: CloseHandle clears it under the global lock, and the
  // slot stays empty (owned by the highest handle to the object, only the last
  // CloseHandle clears it) until a new object is placed there. The
  // relationship between the table and "alive" objects is then:
  //  - while entry.object != null, its reference ("the table's reference")
  //    keeps the object alive, and it is only dropped after the pointer is
  //    cleared, so a non-null pointer can always be dereferenced;
  //  - if we observed the pointer before it was cleared, Retain() still keeps
  //    the object alive even if the clearing thread drops the table's
  //    reference concurrently;
  //  - the re-check below rejects the case where the slot was cleared and
  //    reused by a different object between the load and the Retain.
  object = __atomic_load_n(&entries[slot].object, __ATOMIC_ACQUIRE);
  if (!object) {
    return nullptr;
  }
  object->Retain();
  if (XE_UNLIKELY(__atomic_load_n(&entries[slot].object, __ATOMIC_ACQUIRE) !=
                  object)) {
    // Closed and the slot was reused while we were retaining: this handle now
    // refers to a different object.
    object->Release();
    return nullptr;
  }

  return object;
}

void ObjectTable::GetObjectsByType(XObject::Type type,
                                   std::vector<object_ref<XObject>>* results) {
  auto global_lock = global_critical_region_.Acquire();
  for (uint32_t slot = 0; slot < host_table_capacity_; ++slot) {
    auto& entry = host_table_[slot];
    if (entry.object) {
      if (entry.object->type() == type) {
        entry.object->Retain();
        results->push_back(object_ref<XObject>(entry.object));
      }
    }
  }
  for (uint32_t slot = 0; slot < table_capacity_; ++slot) {
    auto& entry = table_[slot];
    if (entry.object) {
      if (entry.object->type() == type) {
        entry.object->Retain();
        results->push_back(object_ref<XObject>(entry.object));
      }
    }
  }
}

X_HANDLE ObjectTable::TranslateHandle(X_HANDLE handle) {
  // chrispy: reordered these by likelihood, most likely case is that handle is
  // not a special handle
  XE_LIKELY_IF(handle < 0xFFFFFFFE) { return handle; }
  else if (handle == 0xFFFFFFFF) {
    return 0;
  }
  else {
    return XThread::GetCurrentThreadHandle();
  }
}

X_STATUS ObjectTable::AddNameMapping(const std::string_view name,
                                     X_HANDLE handle) {
  auto global_lock = global_critical_region_.Acquire();
  if (name_table_.count(string_key_case(name))) {
    return X_STATUS_OBJECT_NAME_COLLISION;
  }
  name_table_.insert({string_key_case::create(name), handle});
  return X_STATUS_SUCCESS;
}

void ObjectTable::RemoveNameMapping(const std::string_view name) {
  // Names are case-insensitive.
  auto global_lock = global_critical_region_.Acquire();
  auto it = name_table_.find(string_key_case(name));
  if (it != name_table_.end()) {
    name_table_.erase(it);
  }
}

X_STATUS ObjectTable::GetObjectByName(const std::string_view name,
                                      X_HANDLE* out_handle) {
  // Names are case-insensitive.
  auto global_lock = global_critical_region_.Acquire();
  auto it = name_table_.find(string_key_case(name));
  if (it == name_table_.end()) {
    *out_handle = X_INVALID_HANDLE_VALUE;
    return X_STATUS_OBJECT_NAME_NOT_FOUND;
  }
  *out_handle = it->second;

  // We need to ref the handle. I think.
  auto obj = LookupObject(it->second, true);
  if (obj) {
    obj->RetainHandle();
    obj->Release();
  }

  return X_STATUS_SUCCESS;
}

bool ObjectTable::Save(ByteStream* stream) {
  stream->Write<uint32_t>(host_table_capacity_);
  for (uint32_t i = 0; i < host_table_capacity_; i++) {
    auto& entry = host_table_[i];
    stream->Write<int32_t>(entry.handle_ref_count);
  }

  stream->Write<uint32_t>(table_capacity_);
  for (uint32_t i = 0; i < table_capacity_; i++) {
    auto& entry = table_[i];
    stream->Write<int32_t>(entry.handle_ref_count);
  }

  return true;
}

bool ObjectTable::Restore(ByteStream* stream) {
  Resize(stream->Read<uint32_t>(), true);
  for (uint32_t i = 0; i < host_table_capacity_; i++) {
    auto& entry = host_table_[i];
    // entry.object = nullptr;
    entry.handle_ref_count = stream->Read<int32_t>();
  }

  Resize(stream->Read<uint32_t>(), false);
  for (uint32_t i = 0; i < table_capacity_; i++) {
    auto& entry = table_[i];
    // entry.object = nullptr;
    entry.handle_ref_count = stream->Read<int32_t>();
  }

  return true;
}

X_STATUS ObjectTable::RestoreHandle(X_HANDLE handle, XObject* object) {
  const bool is_host_object = XObject::is_handle_host_object(handle);
  uint32_t slot = GetHandleSlot(handle, is_host_object);
  uint32_t capacity = is_host_object ? host_table_capacity_ : table_capacity_;
  assert_true(capacity >= slot);

  if (capacity >= slot) {
    auto& entry = is_host_object ? host_table_[slot] : table_[slot];
    object->Retain();
    __atomic_store_n(&entry.object, object, __ATOMIC_RELEASE);
  }

  return X_STATUS_SUCCESS;
}

}  // namespace util
}  // namespace kernel
}  // namespace xe
