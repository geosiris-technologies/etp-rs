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
pub enum IndexDirection {
    /* None */
    #[serde(rename(serialize = "Increasing", deserialize = "Increasing"))]
    Increasing,
    #[serde(rename(serialize = "Decreasing", deserialize = "Decreasing"))]
    Decreasing,
    #[serde(rename(serialize = "Unordered", deserialize = "Unordered"))]
    Unordered,
}

impl fmt::Display for IndexDirection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                IndexDirection::Increasing => "Increasing",
                IndexDirection::Decreasing => "Decreasing",
                IndexDirection::Unordered => "Unordered",
            }
        )
    }
}

impl FromStr for IndexDirection {
    type Err = ();
    fn from_str(input: &str) -> Result<IndexDirection, Self::Err> {
        match input {
            "Increasing" => Ok(IndexDirection::Increasing),
            "Decreasing" => Ok(IndexDirection::Decreasing),
            "Unordered" => Ok(IndexDirection::Unordered),
            _ => Err(()),
        }
    }
}

impl IndexDirection {
    pub fn iter() -> Iter<'static, IndexDirection> {
        static VEC_ENUM: [IndexDirection; 3] = [
            IndexDirection::Increasing,
            IndexDirection::Decreasing,
            IndexDirection::Unordered,
        ];
        VEC_ENUM.iter()
    }
}
