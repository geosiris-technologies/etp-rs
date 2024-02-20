// SPDX-FileCopyrightText: 2023 Geosiris
// SPDX-License-Identifier: Apache-2.0 OR MIT
#![allow(unused_imports)]

// pub use uuid::{uuid, Uuid};
use uuid::{uuid, Uuid as _Uuid};

pub type Uuid = [u8; 16];

pub fn random_uuid() -> Uuid {
    *_Uuid::new_v4().as_bytes()
}
