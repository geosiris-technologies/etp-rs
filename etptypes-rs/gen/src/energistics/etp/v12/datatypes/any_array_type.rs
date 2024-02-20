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
pub enum AnyArrayType {
    /* None */
    #[serde(rename(serialize = "arrayOfBoolean", deserialize = "arrayOfBoolean"))]
    ArrayOfBoolean,
    #[serde(rename(serialize = "arrayOfInt", deserialize = "arrayOfInt"))]
    ArrayOfInt,
    #[serde(rename(serialize = "arrayOfLong", deserialize = "arrayOfLong"))]
    ArrayOfLong,
    #[serde(rename(serialize = "arrayOfFloat", deserialize = "arrayOfFloat"))]
    ArrayOfFloat,
    #[serde(rename(serialize = "arrayOfDouble", deserialize = "arrayOfDouble"))]
    ArrayOfDouble,
    #[serde(rename(serialize = "arrayOfString", deserialize = "arrayOfString"))]
    ArrayOfString,
    #[serde(rename(serialize = "bytes", deserialize = "bytes"))]
    Bytes,
}

impl fmt::Display for AnyArrayType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                AnyArrayType::ArrayOfBoolean => "arrayOfBoolean",
                AnyArrayType::ArrayOfInt => "arrayOfInt",
                AnyArrayType::ArrayOfLong => "arrayOfLong",
                AnyArrayType::ArrayOfFloat => "arrayOfFloat",
                AnyArrayType::ArrayOfDouble => "arrayOfDouble",
                AnyArrayType::ArrayOfString => "arrayOfString",
                AnyArrayType::Bytes => "bytes",
            }
        )
    }
}

impl FromStr for AnyArrayType {
    type Err = ();
    fn from_str(input: &str) -> Result<AnyArrayType, Self::Err> {
        match input {
            "arrayOfBoolean" => Ok(AnyArrayType::ArrayOfBoolean),
            "arrayOfInt" => Ok(AnyArrayType::ArrayOfInt),
            "arrayOfLong" => Ok(AnyArrayType::ArrayOfLong),
            "arrayOfFloat" => Ok(AnyArrayType::ArrayOfFloat),
            "arrayOfDouble" => Ok(AnyArrayType::ArrayOfDouble),
            "arrayOfString" => Ok(AnyArrayType::ArrayOfString),
            "bytes" => Ok(AnyArrayType::Bytes),
            _ => Err(()),
        }
    }
}

impl AnyArrayType {
    pub fn iter() -> Iter<'static, AnyArrayType> {
        static VEC_ENUM: [AnyArrayType; 7] = [
            AnyArrayType::ArrayOfBoolean,
            AnyArrayType::ArrayOfInt,
            AnyArrayType::ArrayOfLong,
            AnyArrayType::ArrayOfFloat,
            AnyArrayType::ArrayOfDouble,
            AnyArrayType::ArrayOfString,
            AnyArrayType::Bytes,
        ];
        VEC_ENUM.iter()
    }
}
