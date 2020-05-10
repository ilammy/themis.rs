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

use soter::crc;

macro_rules! bench_crc32_fn {
    ($bench_name:ident, $group_name:expr, $update_crc:expr) => {
        fn $bench_name(c: &mut Criterion) {
            let sizes = &[8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096];
            let buffer = vec![0; *sizes.iter().max().unwrap()];

            let plot_config = PlotConfiguration::default().summary_scale(AxisScale::Logarithmic);

            let mut group = c.benchmark_group($group_name);
            group.plot_config(plot_config);

            for size in sizes {
                group.throughput(Throughput::Bytes(*size as u64));
                group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &size| {
                    #[allow(unused_unsafe)]
                    b.iter(|| unsafe {
                        let mut result = crc::INIT_CRC32;
                        result = $update_crc(result, &buffer[0..size]);
                        result = (!result).swap_bytes();
                        criterion::black_box(result);
                    });
                });
            }

            group.finish();
        }
    };
}

bench_crc32_fn!(
    crc32c_choice_runtime,
    "CRC-32C::runtime",
    crc::platform::update_crc32c_runtime
);
bench_crc32_fn!(
    crc32c_choice_lazy,
    "CRC-32C::lazy",
    crc::platform::update_crc32c_lazy
);
bench_crc32_fn!(
    crc32c_software,
    "CRC-32C::software",
    crc::platform::software::update_crc32c
);

// We assume SSE 4.2 is supported on x86 machines running this benchmark.

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
bench_crc32_fn!(
    crc32c_sse42_choice,
    "CRC-32C::sse42",
    crc::platform::sse42::update_crc32c
);
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
bench_crc32_fn!(
    crc32c_sse42_linear,
    "CRC-32C::sse42_linear",
    crc::platform::sse42::update_crc32c_linear
);
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
bench_crc32_fn!(
    crc32c_sse42_unrolled,
    "CRC-32C::sse42_unrolled",
    crc::platform::sse42::update_crc32c_unrolled
);

#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
criterion_group!(
    soter_crc32,
    crc32c_choice_runtime,
    crc32c_choice_lazy,
    crc32c_software,
);

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
criterion_group!(
    soter_crc32,
    crc32c_choice_runtime,
    crc32c_choice_lazy,
    crc32c_software,
    crc32c_sse42_choice,
    crc32c_sse42_linear,
    crc32c_sse42_unrolled,
);

criterion_main!(soter_crc32);
