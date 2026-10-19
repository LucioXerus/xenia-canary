/**
 ******************************************************************************
 * Xenia : Xbox 360 Emulator Research Project                                 *
 ******************************************************************************
 * Copyright 2015 Ben Vanik. All rights reserved.                             *
 * Released under the BSD license - see LICENSE in the root for more details. *
 ******************************************************************************
 */

#ifndef XENIA_BASE_MUTEX_H_
#define XENIA_BASE_MUTEX_H_
#include <atomic>
#include <mutex>
#include <thread>
#include "platform.h"
#if XE_PLATFORM_WIN32
#include "platform_win.h"
#else
#include <sys/types.h>
#endif
#include "memory.h"
#define XE_ENABLE_FAST_WIN32_MUTEX 1
#define XE_ENABLE_FAST_LINUX_MUTEX 1
namespace xe {

#if XE_PLATFORM_WIN32 == 1 && XE_ENABLE_FAST_WIN32_MUTEX == 1
// Recursive mutex using SRWLOCK.
class alignas(4096) xe_global_mutex {
  SRWLOCK srwlock_ = SRWLOCK_INIT;
  DWORD owner_thread_ = 0;
  uint32_t recursion_count_ = 0;

 public:
  xe_global_mutex() = default;
  ~xe_global_mutex() = default;

  void lock();
  void unlock();
  bool try_lock();
};
using global_mutex_type = xe_global_mutex;

// Non-recursive mutex using SRWLOCK.
class alignas(64) xe_fast_mutex {
  SRWLOCK srwlock_ = SRWLOCK_INIT;
  DWORD owner_thread_ = 0;

 public:
  xe_fast_mutex() = default;
  ~xe_fast_mutex() = default;

  void lock();
  void unlock();
  bool try_lock();
};
// a mutex that is extremely unlikely to ever be locked
// use for race conditions that have extremely remote odds of happening
class xe_unlikely_mutex {
  std::atomic<uint32_t> mut;
  bool _tryget() {
    uint32_t lock_expected = 0;
    return mut.compare_exchange_strong(lock_expected, 1);
  }

 public:
  xe_unlikely_mutex() : mut(0) {}
  ~xe_unlikely_mutex() { mut = 0; }

  void lock() {
    if (XE_LIKELY(_tryget())) {
      return;
    } else {
      do {
        // chrispy: warning, if no SMT, mm_pause does nothing...
#if XE_ARCH_AMD64 == 1
        _mm_pause();
#endif

      } while (!_tryget());
    }
  }
  void unlock() { mut.exchange(0); }
  bool try_lock() { return _tryget(); }
};
using xe_mutex = xe_fast_mutex;
#elif XE_PLATFORM_LINUX == 1 && XE_ENABLE_FAST_LINUX_MUTEX == 1

// Short spin budget: this lock is held by guest threads for potentially long
// stretches, so spinning in a tight CAS loop on every contention merely burns
// cycles on the holder's cache line and delays the holder being scheduled.
#define XE_LINUX_MUTEX_SPINCOUNT 24

// Futex timeouts used for adaptive spinning when blocked. after 2, the waiter
// stops sleeping for the full duration of whatever the owner is doing and
// retries the lock; before 2, it has just woken up and steals uncontended
// acquisitions without queueing a futex wake.
static constexpr long XE_LINUX_MUTEX_ADAPTIVE_SPIN_NS = 100000;  // 100 us

// Recursive mutex for Linux backed by futexes.
//
// Fast paths (uncontended lock/unlock) are a single atomic instruction each.
// That is critical here: this guards the global critical region (object table,
// thread state, many kernel calls), so every guest CPU thread takes and
// releases it thousands of times per guest millisecond.
//
// Contention: the first holder upgrades the state to "contended", so releasing
// it wakes one waiter immediately (no missed wakeup, no second round trip).
// Waiters spend a short budget in a non-competing CAS loop -> a compressed
// exponential backoff with sched_yield -> a double-checked futex wait with an
// adaptive timeout so they can steal the lock if the owner keeps it for a
// while. This replaces the previous "spin 128 times then futex, wake one"
// scheme whose cost was essentially one context-switch round trip per
// contended acquisition.
class alignas(4096) xe_global_mutex {
  static constexpr uint32_t kUnlocked = 0;
  static constexpr uint32_t kLocked = 1;
  static constexpr uint32_t kContended = 2;

  std::atomic<uint32_t> state_{kUnlocked};
  pthread_t owner_{0};  // Owner when locked, 0 when free.
  uint32_t recursion_count_{0};

  void lock_slow();
  void unlock_slow();

 public:
  xe_global_mutex() = default;
  ~xe_global_mutex() = default;

  void lock() {
    uint32_t expected = kUnlocked;
    if (XE_LIKELY(state_.compare_exchange_strong(
            expected, kLocked, std::memory_order_acquire,
            std::memory_order_relaxed))) {
      owner_ = pthread_self();
      recursion_count_ = 1;
      return;
    }
    lock_slow();
  }

  void unlock() {
    if (XE_LIKELY(recursion_count_ == 1)) {
      owner_ = 0;
      // Exchange, not store: the previous value tells us if we must wake.
      if (XE_LIKELY(state_.exchange(kUnlocked, std::memory_order_release) ==
                    kLocked)) {
        return;  // Nobody waiting.
      }
    }
    unlock_slow();
  }

  bool try_lock();
};
using global_mutex_type = xe_global_mutex;

// Fast non-recursive mutex for Linux using futex
class alignas(64) xe_fast_mutex {
  std::atomic<uint32_t> state_{0};  // 0 = unlocked, 1 = locked, 2 = contended

  void lock_slow();

 public:
  xe_fast_mutex() = default;
  ~xe_fast_mutex() = default;

  void lock();
  void unlock();
  bool try_lock();
};

// xe_unlikely_mutex remains a simple spinlock for Linux too
class xe_unlikely_mutex {
  std::atomic<uint32_t> mut{0};
  bool _tryget() {
    uint32_t lock_expected = 0;
    return mut.compare_exchange_strong(
        lock_expected, 1, std::memory_order_acquire, std::memory_order_relaxed);
  }

 public:
  xe_unlikely_mutex() = default;
  ~xe_unlikely_mutex() = default;

  void lock() {
    if (XE_LIKELY(_tryget())) {
      return;
    }
    // Spin a bit before yielding. Test-and-test-and-set: only attempt the CAS
    // (_tryget) once a relaxed load shows the lock is free, to avoid the
    // cache-line contention and memory-ordering machine clears of a
    // CAS-per-iteration spin.
    for (int i = 0; i < XE_LINUX_MUTEX_SPINCOUNT; ++i) {
#if XE_ARCH_AMD64 == 1
      _mm_pause();
#endif
      if (mut.load(std::memory_order_relaxed) == 0 && _tryget()) {
        return;
      }
    }
    // Fall back to yielding
    while (true) {
      if (mut.load(std::memory_order_relaxed) == 0 && _tryget()) {
        return;
      }
      std::this_thread::yield();
    }
  }
  void unlock() { mut.store(0, std::memory_order_release); }
  bool try_lock() { return _tryget(); }
};

using xe_mutex = xe_fast_mutex;
#else
using global_mutex_type = std::recursive_mutex;
using xe_mutex = std::mutex;
using xe_unlikely_mutex = std::mutex;
#endif
struct null_mutex {
 public:
  static void lock() {}
  static void unlock() {}
  static bool try_lock() { return true; }
};

using global_unique_lock_type = std::unique_lock<global_mutex_type>;
// The global critical region mutex singleton.
// This must guard any operation that may suspend threads or be sensitive to
// being suspended such as global table locks and such.
// To prevent deadlocks this should be the first lock acquired and be held
// for the entire duration of the critical region (longer than any other lock).
//
// As a general rule if some code can only be accessed from the guest you can
// guard it with only the global critical region and be assured nothing else
// will touch it. If it will be accessed from non-guest threads you may need
// some additional protection.
//
// You can think of this as disabling interrupts in the guest. The thread in the
// global critical region has exclusive access to the entire system and cannot
// be preempted. This also means that all activity done while in the critical
// region must be extremely fast (no IO!), as it has the chance to block any
// other thread until its done.
//
// For example, in the following situation thread 1 will not be able to suspend
// thread 0 until it has exited its critical region, preventing it from being
// suspended while holding the table lock:
//   [thread 0]:
//     DoKernelStuff():
//       auto global_lock = global_critical_region_.Acquire();
//       std::lock_guard<std::mutex> table_lock(table_mutex_);
//       table_->InsertStuff();
//   [thread 1]:
//     MySuspendThread():
//       auto global_lock = global_critical_region_.Acquire();
//       ::SuspendThread(thread0);
//
// To use the region it's strongly recommended that you keep an instance near
// the data requiring it. This makes it clear to those reading that the data
// is protected by the global critical region. For example:
// class MyType {
//   // Implies my_list_ is protected:
//   xe::global_critical_region global_critical_region_;
//   std::list<...> my_list_;
// };
class global_critical_region {
 public:
  constexpr global_critical_region() {}
  static global_mutex_type& mutex();

  // Acquires a lock on the global critical section.
  // Use this when keeping an instance is not possible. Otherwise, prefer
  // to keep an instance of global_critical_region near the members requiring
  // it to keep things readable.
  static global_unique_lock_type AcquireDirect() {
    return global_unique_lock_type(mutex());
  }

  // Acquires a lock on the global critical section.
  static inline global_unique_lock_type Acquire() {
    return global_unique_lock_type(mutex());
  }

  static inline void PrepareToAcquire() { swcache::PrefetchW(&mutex()); }

  // Acquires a deferred lock on the global critical section.
  static inline global_unique_lock_type AcquireDeferred() {
    return global_unique_lock_type(mutex(), std::defer_lock);
  }

  // Tries to acquire a lock on the glboal critical section.
  // Check owns_lock() to see if the lock was successfully acquired.
  static inline global_unique_lock_type TryAcquire() {
    return global_unique_lock_type(mutex(), std::try_to_lock);
  }
};

}  // namespace xe

#endif  // XENIA_BASE_MUTEX_H_
