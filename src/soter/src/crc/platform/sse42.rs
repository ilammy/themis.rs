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

//! SSE 4.2 implementations of CRC.
//!
//! All functions here are **unsafe**.
//! Ensure SSE 4.2 availability with `is_x86_feature_detected!("sse4.2")` before calling them.

/// Threshold for using unrolled CRC-32C computation.
///
/// [`update_crc32c_unrolled`](fn.update_crc32c_unrolled.html) is faster than
/// [`update_crc32c_linear`](fn.update_crc32c_linear.html) on data buffers longer than this.
pub const CRC32C_UNROLL_THRESHOLD: usize = 16;

/// Updates CRC-32C state using the best `crc32` instruction.
///
/// # Safety
///
/// This function uses SSE 4.2 instructions.
/// Make sure the CPU supports them before calling this function.
/// Otherwise the process will typically be killed by the operating system.
#[target_feature(enable = "sse4.2")]
pub unsafe fn update_crc32c(state: u32, data: &[u8]) -> u32 {
    if data.len() >= CRC32C_UNROLL_THRESHOLD {
        update_crc32c_unrolled(state, data)
    } else {
        update_crc32c_linear(state, data)
    }
}

/// Updates CRC-32C state using `crc32 r32, r8` instruction.
///
/// This is about 3-4 times faster than [`software::update_crc32c`](../software/fn.update_crc32c.html).
///
/// # Safety
///
/// This function uses SSE 4.2 instructions.
/// Make sure the CPU supports them before calling this function.
/// Otherwise the process will typically be killed by the operating system.
#[target_feature(enable = "sse4.2")]
pub unsafe fn update_crc32c_linear(mut state: u32, data: &[u8]) -> u32 {
    #[cfg(target_arch = "x86")]
    use std::arch::x86::_mm_crc32_u8;
    #[cfg(target_arch = "x86_64")]
    use std::arch::x86_64::_mm_crc32_u8;
    for byte in data {
        state = _mm_crc32_u8(state, *byte);
    }
    state
}

/// Updates CRC-32C state using `crc32 r32, r32` instruction.
///
/// This is about 4-8 times faster than [`update_crc32c_linear`](fn.update_crc32c_linear.html),
/// given sufficient runway.
///
/// # Safety
///
/// This function uses SSE 4.2 instructions.
/// Make sure the CPU supports them before calling this function.
/// Otherwise the process will typically be killed by the operating system.
#[target_feature(enable = "sse4.2")]
#[cfg(target_arch = "x86")]
pub unsafe fn update_crc32c_unrolled(mut state: u32, data: &[u8]) -> u32 {
    use std::arch::x86::{_mm_crc32_u32, _mm_crc32_u8};
    let (prefix, dwords, suffix) = data.align_to();
    for byte in prefix {
        state = _mm_crc32_u8(state, *byte);
    }
    for dword in dwords {
        state = _mm_crc32_u32(state, *dword);
    }
    for byte in suffix {
        state = _mm_crc32_u8(state, *byte);
    }
    state
}

/// Updates CRC-32C state using `crc32 r64, r64` instruction.
///
/// This is up to 8-10 times faster than [`update_crc32c_linear`](fn.update_crc32c_linear.html),
/// given sufficient runway.
///
/// # Safety
///
/// This function uses SSE 4.2 instructions.
/// Make sure the CPU supports them before calling this function.
/// Otherwise the process will typically be killed by the operating system.
#[target_feature(enable = "sse4.2")]
#[cfg(target_arch = "x86_64")]
pub unsafe fn update_crc32c_unrolled(mut state: u32, data: &[u8]) -> u32 {
    use std::arch::x86_64::{_mm_crc32_u64, _mm_crc32_u8};
    let (prefix, qwords, suffix) = data.align_to();
    for byte in prefix {
        state = _mm_crc32_u8(state, *byte);
    }
    let mut state64 = state as u64;
    for qword in qwords {
        state64 = _mm_crc32_u64(state64, *qword);
    }
    state = state64 as u32;
    for byte in suffix {
        state = _mm_crc32_u8(state, *byte);
    }
    state
}

#[cfg(test)]
mod tests {
    mod crc32c {
        use crate::crc::platform::{software, sse42};
        use crate::crc::INIT_CRC32;
        use crate::rand;

        // Make sure that optimized behavior is identical to software implementation.
        // Especially for the unrolled code which requires careful address alignment
        // and has some edge cases related to that.
        #[test]
        fn same_as_software() {
            if !is_x86_feature_detected!("sse4.2") {
                return;
            }
            let mut input = [0; 256];
            rand::bytes(&mut input);
            for length in 0..=input.len() {
                unsafe {
                    let input = &input[0..length];
                    let software = software::update_crc32c(INIT_CRC32, input);
                    let sse42_linear = sse42::update_crc32c_linear(INIT_CRC32, input);
                    let sse42_unrolled = sse42::update_crc32c_unrolled(INIT_CRC32, input);
                    assert_eq!(sse42_linear, software);
                    assert_eq!(sse42_unrolled, software);
                }
            }
        }
    }
}
