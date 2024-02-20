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
pub enum PassDirection {
    /* None */
    #[serde(rename(serialize = "Up", deserialize = "Up"))]
    Up,
    #[serde(rename(serialize = "HoldingSteady", deserialize = "HoldingSteady"))]
    HoldingSteady,
    #[serde(rename(serialize = "Down", deserialize = "Down"))]
    Down,
}

impl fmt::Display for PassDirection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                PassDirection::Up => "Up",
                PassDirection::HoldingSteady => "HoldingSteady",
                PassDirection::Down => "Down",
            }
        )
    }
}

impl FromStr for PassDirection {
    type Err = ();
    fn from_str(input: &str) -> Result<PassDirection, Self::Err> {
        match input {
            "Up" => Ok(PassDirection::Up),
            "HoldingSteady" => Ok(PassDirection::HoldingSteady),
            "Down" => Ok(PassDirection::Down),
            _ => Err(()),
        }
    }
}

impl PassDirection {
    pub fn iter() -> Iter<'static, PassDirection> {
        static VEC_ENUM: [PassDirection; 3] = [
            PassDirection::Up,
            PassDirection::HoldingSteady,
            PassDirection::Down,
        ];
        VEC_ENUM.iter()
    }
}
