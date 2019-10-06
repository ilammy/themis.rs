// Copyright 2019 themis.rs maintainers
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

use soter::rand;

fn bytes(c: &mut Criterion) {
    let sizes = &[0, 8, 64, 512, 4096, 32768, 262_144, 2_097_152];
    let mut buffer = vec![0; *sizes.iter().max().unwrap()];

    let plot_config = PlotConfiguration::default()
        .summary_scale(AxisScale::Logarithmic);

    let mut group = c.benchmark_group("rand::bytes()");
    group.plot_config(plot_config);

    for size in sizes {
        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &size| {
            b.iter(|| rand::bytes(&mut buffer[0..size]));
        });
    }
    group.finish();
}

criterion_group!(soter_rand, bytes);

criterion_main!(soter_rand);
