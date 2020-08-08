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

#[macro_use]
extern crate criterion;

use criterion::{AxisScale, BenchmarkId, Criterion, PlotConfiguration, Throughput};

use boringssl_sys::{
    EVP_DigestFinal_ex, EVP_DigestInit_ex, EVP_DigestUpdate, EVP_MD_CTX_create, EVP_MD_CTX_destroy,
    EVP_sha256, EVP_sha512,
};
use soter::hash::{Algorithm, Hash};

fn benchmark_hash_function(
    c: &mut Criterion,
    group_name: &str,
    compute_hash: impl Fn(&[u8], &mut [u8]),
) {
    let sizes = &[8, 64, 512, 4096, 32768, 256 * 1024, 2 * 1024 * 1024];
    let buffer = vec![0; *sizes.iter().max().unwrap()];

    let plot_config = PlotConfiguration::default().summary_scale(AxisScale::Logarithmic);

    let mut group = c.benchmark_group(group_name);
    group.plot_config(plot_config);

    for size in sizes {
        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &size| {
            let mut result = [0; 64]; // enough for all SHA-2
            b.iter(|| {
                compute_hash(&buffer[0..size], &mut result);
                criterion::black_box(result);
            });
        });
    }

    group.finish();
}

// How much does it take for Rust API to compute hashes, while performing
// all additional safety checks.

fn sha_256_rust(c: &mut Criterion) {
    benchmark_hash_function(c, "hash::SHA-256::Rust", |input, output| {
        let mut hash = Hash::new(Algorithm::SHA256);
        hash.write(input);
        let _ = hash.finalise(output);
    });
}

fn sha_512_rust(c: &mut Criterion) {
    benchmark_hash_function(c, "hash::SHA-512::Rust", |input, output| {
        let mut hash = Hash::new(Algorithm::SHA512);
        hash.write(input);
        let _ = hash.finalise(output);
    });
}

// How much it ideally takes with direct BoringSSL calls, without validation,
// assuming correct arguments, etc.

fn sha_256_ffi(c: &mut Criterion) {
    benchmark_hash_function(c, "hash::SHA-256::FFI", |input, output| {
        use std::ffi::c_void as void;
        unsafe {
            let ctx = EVP_MD_CTX_create();
            EVP_DigestInit_ex(ctx, EVP_sha256(), std::ptr::null_mut());
            EVP_DigestUpdate(ctx, input.as_ptr() as *mut void, input.len());
            EVP_DigestFinal_ex(ctx, output.as_mut_ptr(), std::ptr::null_mut());
            EVP_MD_CTX_destroy(ctx);
        }
    });
}

fn sha_512_ffi(c: &mut Criterion) {
    benchmark_hash_function(c, "hash::SHA-512::FFI", |input, output| {
        use std::ffi::c_void as void;
        unsafe {
            let ctx = EVP_MD_CTX_create();
            EVP_DigestInit_ex(ctx, EVP_sha512(), std::ptr::null_mut());
            EVP_DigestUpdate(ctx, input.as_ptr() as *mut void, input.len());
            EVP_DigestFinal_ex(ctx, output.as_mut_ptr(), std::ptr::null_mut());
            EVP_MD_CTX_destroy(ctx);
        }
    });
}

criterion_group!(
    soter_hash,
    sha_256_rust,
    sha_256_ffi,
    sha_512_rust,
    sha_512_ffi,
);

criterion_main!(soter_hash);
