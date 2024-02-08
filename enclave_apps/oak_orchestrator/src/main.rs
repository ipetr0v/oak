//
// Copyright 2024 The Project Oak Authors
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
//

#![no_std]
#![no_main]
#![feature(alloc_error_handler)]

extern crate alloc;

use oak_dice::evidence::Stage0DiceData;
use oak_restricted_kernel_interface::{syscall::read, DICE_DATA_FD};
use oak_restricted_kernel_sdk::{channel::FileDescriptorChannel, entrypoint};
use zerocopy::{AsBytes, FromZeroes};

fn read_stage0_dice_data() -> Stage0DiceData {
    let mut result = Stage0DiceData::new_zeroed();
    let buffer = result.as_bytes_mut();
    let len = read(DICE_DATA_FD, buffer).expect("failed to read dice data");
    assert!(len == buffer.len(), "invalid dice data size");
    result
}

#[entrypoint]
fn start() -> ! {
    let dice_data = read_stage0_dice_data();
    let channel = FileDescriptorChannel::default();
    oak_restricted_kernel_orchestrator::entrypoint(channel, dice_data)
}