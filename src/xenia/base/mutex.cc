/**
 ******************************************************************************
 * Xenia : Xbox 360 Emulator Research Project                                 *
 ******************************************************************************
 * Copyright 2015 Ben Vanik. All rights reserved.                             *
 * Released under the BSD license - see LICENSE in the root for more details. *
 ******************************************************************************
 */

#include "xenia/base/mutex.h"
#if XE_PLATFORM_WIN32 == 1
#include "xenia/base/platform_win.h"
#elif XE_PLATFORM_LINUX == 1
#include <linux/futex.h>
#include <pthread.h>
#include <sched.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <time.h>
#endif

namespace xe {
#if XE_PLATFORM_WIN32 == 1 && XE_ENABLE_FAST_WIN32_MUTEX == 1

// xe_global_mutex: recursive mutex via SRWLOCK
void xe_global_mutex::lock() {
  DWORD self = GetCurrentThreadId();
  if (owner_thread_ == self) {
    ++recursion_count_;
    return;
  }
  AcquireSRWLockExclusive(&srwlock_);
  owner_thread_ = self;
  recursion_count_ = 1;
}

void xe_global_mutex::unlock() {
  if (--recursion_count_ == 0) {
    owner_thread_ = 0;
    ReleaseSRWLockExclusive(&srwlock_);
  }
}

bool xe_global_mutex::try_lock() {
  DWORD self = GetCurrentThreadId();
  if (owner_thread_ == self) {
    ++recursion_count_;
    return true;
  }
  if (TryAcquireSRWLockExclusive(&srwlock_)) {
    owner_thread_ = self;
    recursion_count_ = 1;
    return true;
  }
  return false;
}

// xe_fast_mutex: non-recursive mutex via SRWLOCK
void xe_fast_mutex::lock() {
  DWORD self = GetCurrentThreadId();
  if (owner_thread_ == self) {
    assert_always("xe_fast_mutex: recursive lock detected");
  }
  AcquireSRWLockExclusive(&srwlock_);
  owner_thread_ = self;
}

void xe_fast_mutex::unlock() {
  owner_thread_ = 0;
  ReleaseSRWLockExclusive(&srwlock_);
}

bool xe_fast_mutex::try_lock() {
  if (TryAcquireSRWLockExclusive(&srwlock_)) {
    owner_thread_ = GetCurrentThreadId();
    return true;
  }
  return false;
}
#elif XE_PLATFORM_LINUX == 1 && XE_ENABLE_FAST_LINUX_MUTEX == 1

namespace {

inline int futex_wait(std::atomic<uint32_t>* addr, uint32_t expected) {
  return syscall(SYS_futex, addr, FUTEX_WAIT_PRIVATE, expected, nullptr,
                 nullptr, 0);
}

inline int futex_wake(std::atomic<uint32_t>* addr, int count) {
  return syscall(SYS_futex, addr, FUTEX_WAKE_PRIVATE, count, nullptr, nullptr,
                 0);
}

inline int futex_wait_timeout(std::atomic<uint32_t>* addr, uint32_t expected,
                              const struct timespec* timeout) {
  return syscall(SYS_futex, addr, FUTEX_WAIT_PRIVATE, expected, timeout,
                 nullptr, 0);
}

// Blocked before this many times: this is a "cheap" wake (the owner will
// release soon, or the guest thread will be scheduled again soon), so spin
// without sleeping afterwards so we can steal the lock if it is free.
static constexpr int kAdaptiveSpinWaiters = 2;

}  // namespace

// xe_global_mutex implementation (recursive)
void xe_global_mutex::lock_slow() {
  pthread_t self = pthread_self();

  // Recursive acquisition - the owner's CAS above failed because the state is
  // already 1 or 2. Only the owner can observe this, as the state is only ever
  // written by the owner while owner_ == self.
  if (owner_ == self) {
    ++recursion_count_;
    return;
  }

  // Short preliminary spin: many "contended" observations are the tail of an
  // acquisition where the owner is about to release.
  for (int i = 0; i < XE_LINUX_MUTEX_SPINCOUNT; ++i) {
#if XE_ARCH_AMD64 == 1
    _mm_pause();
#endif
    uint32_t expected = kUnlocked;
    if (state_.compare_exchange_strong(expected, kLocked,
                                       std::memory_order_acquire,
                                       std::memory_order_relaxed)) {
      owner_ = self;
      recursion_count_ = 1;
      return;
    }
  }

  // Exponential backoff with yields before queuing on the futex: avoids a
  // thundering herd of futex wakes and gives the owner a chance to finish.
  for (int i = 0; i < 8; ++i) {
    sched_yield();
    uint32_t expected = kUnlocked;
    if (state_.compare_exchange_strong(expected, kLocked,
                                       std::memory_order_acquire,
                                       std::memory_order_relaxed)) {
      owner_ = self;
      recursion_count_ = 1;
      return;
    }
    if (i > 2) {
      // Keep the backoff bounded; the futex wait below does the real sleeping.
      break;
    }
  }

  int wait_count = 0;
  for (;;) {
    // Mark as contended so that the owner wakes a waiter on release.
    uint32_t state = state_.exchange(kContended, std::memory_order_acquire);
    if (state == kUnlocked) {
      // We got the lock while marking it contended.
      owner_ = self;
      recursion_count_ = 1;
      return;
    }

    if (wait_count >= kAdaptiveSpinWaiters) {
      // Steal without sleeping if the lock is free now.
      uint32_t expected = kUnlocked;
      if (state_.compare_exchange_strong(expected, kContended,
                                         std::memory_order_acquire,
                                         std::memory_order_relaxed)) {
        owner_ = self;
        recursion_count_ = 1;
        return;
      }
    }

    struct timespec timeout;
    timeout.tv_sec = 0;
    timeout.tv_nsec = XE_LINUX_MUTEX_ADAPTIVE_SPIN_NS;
    if (futex_wait_timeout(&state_, kContended, &timeout) == 0) {
      // Woken by the owner's futex_wake: the lock was released then possibly
      // re-acquired. Try once without sleeping, then sleep for real so we
      // don't spin on a long-held lock.
      uint32_t expected = kUnlocked;
      if (state_.compare_exchange_strong(expected, kContended,
                                         std::memory_order_acquire,
                                         std::memory_order_relaxed)) {
        owner_ = self;
        recursion_count_ = 1;
        return;
      }
      ++wait_count;
    } else {
      // Timeout or spurious wakeup: the holder may be running long, so try to
      // steal the lock next time around and then sleep without a timeout.
      ++wait_count;
    }
  }
}

void xe_global_mutex::unlock_slow() {
  if (recursion_count_ > 1) {
    --recursion_count_;
    return;  // Still have recursive locks
  }

  owner_ = 0;
  // unlock() already published kUnlocked before calling this; reaching the slow
  // path means it observed the contended state, so a waiter is queued on the
  // futex and must be woken exactly once. Re-exchanging the state here would
  // read kUnlocked again and silently lose that wakeup.
  futex_wake(&state_, 1);
}

bool xe_global_mutex::try_lock() {
  pthread_t self = pthread_self();

  // Check for recursive lock
  if (owner_ == self) {
    ++recursion_count_;
    return true;
  }

  uint32_t expected = kUnlocked;
  if (state_.compare_exchange_strong(expected, kLocked,
                                     std::memory_order_acquire,
                                     std::memory_order_relaxed)) {
    owner_ = self;
    recursion_count_ = 1;
    return true;
  }
  return false;
}

// xe_fast_mutex implementation (non-recursive)
void xe_fast_mutex::lock() {
  // Fast path: uncontended
  uint32_t expected = 0;
  if (XE_LIKELY(state_.compare_exchange_strong(
          expected, 1, std::memory_order_acquire, std::memory_order_relaxed))) {
    return;
  }

  lock_slow();
}

void xe_fast_mutex::lock_slow() {
  // Spin phase
  for (int i = 0; i < XE_LINUX_MUTEX_SPINCOUNT; ++i) {
#if XE_ARCH_AMD64 == 1
    _mm_pause();
#endif
    uint32_t expected = 0;
    if (state_.compare_exchange_strong(expected, 1, std::memory_order_acquire,
                                       std::memory_order_relaxed)) {
      return;
    }
  }

  // Slow path: use futex
  while (true) {
    // Mark as contended (state = 2) and wait
    uint32_t state = state_.exchange(2, std::memory_order_acquire);
    if (state == 0) {
      // We got the lock while marking contended
      return;
    }

    // Wait on futex
    futex_wait(&state_, 2);

    // Try to acquire after wakeup
    uint32_t expected = 0;
    if (state_.compare_exchange_strong(expected, 2, std::memory_order_acquire,
                                       std::memory_order_relaxed)) {
      return;
    }
  }
}

void xe_fast_mutex::unlock() {
  // If state was 2 (contended), we need to wake a waiter
  if (state_.exchange(0, std::memory_order_release) == 2) {
    futex_wake(&state_, 1);
  }
}

bool xe_fast_mutex::try_lock() {
  uint32_t expected = 0;
  return state_.compare_exchange_strong(expected, 1, std::memory_order_acquire,
                                        std::memory_order_relaxed);
}

#endif
global_mutex_type& global_critical_region::mutex() {
  static global_mutex_type global_mutex;
  return global_mutex;
}

}  // namespace xe
