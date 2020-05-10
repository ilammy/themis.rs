// Copyright 2020 themis.rs maintainers
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Platform-specific implementations of CRC.

use std::mem::transmute;
use std::sync::atomic::{AtomicPtr, Ordering};

pub mod software;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub mod sse42;

/// Updates CRC-32C state in the most efficient way for the platform.
///
/// The best approach is detected at runtime.
pub fn update_crc32c_runtime(state: u32, data: &[u8]) -> u32 {
    // x86 processors with SSE 4.2 instruction set can compute CRC-32C much faster.
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    unsafe {
        if is_x86_feature_detected!("sse4.2") {
            // We have checked for SSE 4.2 availability, it is safe to proceed.
            return sse42::update_crc32c(state, data);
        }
    }
    // Fall back to pure software implementation on other architectures.
    software::update_crc32c(state, data)
}

// `is_x86_feature_detected!` is not free, for portability it does way more than just `cpuid`.
// (Did you know that not all x86 CPUs support that instruction?)
// It's cheaper to perform the detection only once and record the result into a global state.
// The use of atomics here is sound as we don't really care which thread detects it first,
// or whether multiple threads do it concurrently -- they all end up with the same result.
//
// Though, you should know that AtomicPtr does not truly support function pointers.
// We can weasel our way out for platforms where function pointers are like other pointers.
// If they have the same bitwise layout, size, etc. then `transmute` calls are safe.
//
// Here are some issues tracking this case:
// https://github.com/rust-lang/rfcs/issues/2481
// https://github.com/rust-lang/rust/issues/57563

type FnCRC32 = fn(u32, &[u8]) -> u32;
#[allow(unused)]
type UnsafeFnCRC32 = unsafe fn(u32, &[u8]) -> u32;

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
static UPDATE_CRC32C: AtomicPtr<FnCRC32> = AtomicPtr::new(detect_update_crc32c as *mut FnCRC32);

#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
static UPDATE_CRC32C: AtomicPtr<FnCRC32C> = AtomicPtr::new(software::update_crc32c as *mut FnCRC32);

/// Updates CRC-32C state in the most efficient way for the platform.
///
/// The best approach is detected at runtime lazily, only once.
#[allow(clippy::crosspointer_transmute)]
pub fn update_crc32c_lazy(state: u32, data: &[u8]) -> u32 {
    let crc_ptr = UPDATE_CRC32C.load(Ordering::Relaxed);
    let crc = unsafe { transmute::<*mut FnCRC32, FnCRC32>(crc_ptr) };
    crc(state, data)
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[allow(clippy::crosspointer_transmute)]
fn detect_update_crc32c(state: u32, data: &[u8]) -> u32 {
    let crc = if is_x86_feature_detected!("sse4.2") {
        // We have checked for SSE 4.2 availability, it is safe to lift the "unsafe" marker.
        unsafe { transmute::<UnsafeFnCRC32, FnCRC32>(sse42::update_crc32c) }
    } else {
        software::update_crc32c
    };
    UPDATE_CRC32C.store(crc as *mut FnCRC32, Ordering::Relaxed);
    crc(state, data)
}
