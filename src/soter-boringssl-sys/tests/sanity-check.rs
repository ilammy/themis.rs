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

//! Sanity check for the generated bindings.

use soter_boringssl_sys::RAND_bytes;

#[test]
fn check_csprng() {
    let mut random_data = vec![0; 32];
    let result = unsafe { RAND_bytes(random_data.as_mut_ptr(), random_data.len()) };
    assert_eq!(result, 1);
}
