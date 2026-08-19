use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::UnsafeCell;
use std::fmt;
use std::fmt::{Debug, Display};

use crate::runtime::misc::byte_stuff;

// #[global_allocator]
// static GLOBAL: CountingAllocator = CountingAllocator::new();

#[derive(Debug, Clone, Copy)]
struct AllocationInfo {
    count_total: usize,
    count_current: usize,
    count_max: usize,
    bytes_total: usize,
    bytes_current: usize,
    bytes_max: usize,
}

impl Display for AllocationInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "  total_count = {},\ttotal_bytes={}",
            self.count_total,
            byte_stuff::pretty_bytes(self.bytes_total),
        )?;
        writeln!(
            f,
            "  current_count = {},\tcurrent_bytes={}",
            self.count_current,
            byte_stuff::pretty_bytes(self.bytes_current),
        )?;
        write!(
            f,
            "  peak_count = {},\tpeak_bytes={}",
            self.count_max,
            byte_stuff::pretty_bytes(self.bytes_max),
        )
    }
}

impl AllocationInfo {
    const fn new() -> Self {
        Self {
            count_total: 0,
            count_current: 0,
            count_max: 0,
            bytes_total: 0,
            bytes_current: 0,
            bytes_max: 0,
        }
    }
    fn track_alloc(&mut self, bytes: usize) {
        self.count_total += 1;
        self.count_current += 1;
        self.count_max = self.count_max.max(self.count_current);

        self.bytes_total += bytes;
        self.bytes_current += bytes;
        self.bytes_max = self.bytes_max.max(self.bytes_current);
    }

    fn track_dealloc(&mut self, bytes: usize) {
        debug_assert!(self.count_current > 0);
        debug_assert!(self.bytes_current >= bytes);

        self.count_current -= 1;
        self.bytes_current -= bytes;
    }

    fn diff(&self, previous: Self) -> AllocationInfo {
        AllocationInfo {
            count_total: self.count_total - previous.count_total,
            count_current: 0,
            count_max: self.count_max - previous.count_max,
            bytes_total: self.bytes_total - previous.bytes_total,
            bytes_current: 0,
            bytes_max: self.bytes_max - previous.bytes_max,
        }
    }
}

struct AllocationUsage {
    bytes: usize,
    count: usize,
}

impl fmt::Display for AllocationUsage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} -> {}",
            self.count,
            byte_stuff::pretty_bytes(self.bytes)
        )
    }
}

impl AllocationUsage {
    fn diff(&self, previous: Self) -> AllocationUsage {
        AllocationUsage {
            bytes: self.bytes - previous.bytes,
            count: self.count - previous.count,
        }
    }
}

struct CountingAllocator {
    info: UnsafeCell<AllocationInfo>,
}

impl CountingAllocator {
    const fn new() -> Self {
        Self {
            info: UnsafeCell::new(AllocationInfo::new()),
        }
    }

    fn snapshot(&self) -> AllocationInfo {
        unsafe { *self.info.get() }
    }

    fn usage_snapshot(&self) -> AllocationUsage {
        let info = unsafe { *self.info.get() };

        AllocationUsage {
            bytes: info.bytes_total,
            count: info.count_total,
        }
    }

    #[allow(clippy::mut_from_ref)]
    unsafe fn info_mut(&self) -> &mut AllocationInfo {
        unsafe { &mut *self.info.get() }
    }

    fn measure<F, R>(&self, f: F) -> (R, AllocationUsage)
    where
        F: FnOnce() -> R,
    {
        let before = self.usage_snapshot();
        let result = f();
        let after = self.usage_snapshot();

        (result, after.diff(before))
    }
}

unsafe impl Sync for CountingAllocator {}

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc(layout) };

        if !ptr.is_null() {
            unsafe { self.info_mut().track_alloc(layout.size()) };
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe {
            self.info_mut().track_dealloc(layout.size());
            System.dealloc(ptr, layout)
        }
    }
}
