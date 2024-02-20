// SPDX-FileCopyrightText: 2023 Geosiris
// SPDX-License-Identifier: Apache-2.0 OR MIT
#![allow(unused_imports)]
#![allow(non_camel_case_types)]
use crate::helpers::*;
use apache_avro::{Error, Schema};
use bytes;
use derivative::Derivative;
use std::collections::HashMap;
use std::time::SystemTime;

use crate::helpers::Schemable;
use apache_avro::{from_avro_datum, from_value, AvroResult};
use std::fmt;
use std::io::Read;
use std::slice::Iter;
use std::str::FromStr;

#[derive(Debug, PartialEq, Clone, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "PascalCase")]
pub enum ActiveStatusKind {
    /* None */
    #[serde(rename(serialize = "Active", deserialize = "Active"))]
    Active,
    #[serde(rename(serialize = "Inactive", deserialize = "Inactive"))]
    Inactive,
}

impl fmt::Display for ActiveStatusKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                ActiveStatusKind::Active => "Active",
                ActiveStatusKind::Inactive => "Inactive",
            }
        )
    }
}

impl FromStr for ActiveStatusKind {
    type Err = ();
    fn from_str(input: &str) -> Result<ActiveStatusKind, Self::Err> {
        match input {
            "Active" => Ok(ActiveStatusKind::Active),
            "Inactive" => Ok(ActiveStatusKind::Inactive),
            _ => Err(()),
        }
    }
}

impl ActiveStatusKind {
    pub fn iter() -> Iter<'static, ActiveStatusKind> {
        static VEC_ENUM: [ActiveStatusKind; 2] =
            [ActiveStatusKind::Active, ActiveStatusKind::Inactive];
        VEC_ENUM.iter()
    }
}
