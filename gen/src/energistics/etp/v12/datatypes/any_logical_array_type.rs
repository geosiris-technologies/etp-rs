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
pub enum AnyLogicalArrayType {
    /* None */
    #[serde(rename(serialize = "arrayOfBoolean", deserialize = "arrayOfBoolean"))]
    ArrayOfBoolean,
    #[serde(rename(serialize = "arrayOfInt8", deserialize = "arrayOfInt8"))]
    ArrayOfInt8,
    #[serde(rename(serialize = "arrayOfUInt8", deserialize = "arrayOfUInt8"))]
    ArrayOfUInt8,
    #[serde(rename(serialize = "arrayOfInt16LE", deserialize = "arrayOfInt16LE"))]
    ArrayOfInt16LE,
    #[serde(rename(serialize = "arrayOfInt32LE", deserialize = "arrayOfInt32LE"))]
    ArrayOfInt32LE,
    #[serde(rename(serialize = "arrayOfInt64LE", deserialize = "arrayOfInt64LE"))]
    ArrayOfInt64LE,
    #[serde(rename(serialize = "arrayOfUInt16LE", deserialize = "arrayOfUInt16LE"))]
    ArrayOfUInt16LE,
    #[serde(rename(serialize = "arrayOfUInt32LE", deserialize = "arrayOfUInt32LE"))]
    ArrayOfUInt32LE,
    #[serde(rename(serialize = "arrayOfUInt64LE", deserialize = "arrayOfUInt64LE"))]
    ArrayOfUInt64LE,
    #[serde(rename(serialize = "arrayOfFloat32LE", deserialize = "arrayOfFloat32LE"))]
    ArrayOfFloat32LE,
    #[serde(rename(serialize = "arrayOfDouble64LE", deserialize = "arrayOfDouble64LE"))]
    ArrayOfDouble64LE,
    #[serde(rename(serialize = "arrayOfInt16BE", deserialize = "arrayOfInt16BE"))]
    ArrayOfInt16BE,
    #[serde(rename(serialize = "arrayOfInt32BE", deserialize = "arrayOfInt32BE"))]
    ArrayOfInt32BE,
    #[serde(rename(serialize = "arrayOfInt64BE", deserialize = "arrayOfInt64BE"))]
    ArrayOfInt64BE,
    #[serde(rename(serialize = "arrayOfUInt16BE", deserialize = "arrayOfUInt16BE"))]
    ArrayOfUInt16BE,
    #[serde(rename(serialize = "arrayOfUInt32BE", deserialize = "arrayOfUInt32BE"))]
    ArrayOfUInt32BE,
    #[serde(rename(serialize = "arrayOfUInt64BE", deserialize = "arrayOfUInt64BE"))]
    ArrayOfUInt64BE,
    #[serde(rename(serialize = "arrayOfFloat32BE", deserialize = "arrayOfFloat32BE"))]
    ArrayOfFloat32BE,
    #[serde(rename(serialize = "arrayOfDouble64BE", deserialize = "arrayOfDouble64BE"))]
    ArrayOfDouble64BE,
    #[serde(rename(serialize = "arrayOfString", deserialize = "arrayOfString"))]
    ArrayOfString,
    #[serde(rename(serialize = "arrayOfCustom", deserialize = "arrayOfCustom"))]
    ArrayOfCustom,
}

impl fmt::Display for AnyLogicalArrayType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                AnyLogicalArrayType::ArrayOfBoolean => "arrayOfBoolean",
                AnyLogicalArrayType::ArrayOfInt8 => "arrayOfInt8",
                AnyLogicalArrayType::ArrayOfUInt8 => "arrayOfUInt8",
                AnyLogicalArrayType::ArrayOfInt16LE => "arrayOfInt16LE",
                AnyLogicalArrayType::ArrayOfInt32LE => "arrayOfInt32LE",
                AnyLogicalArrayType::ArrayOfInt64LE => "arrayOfInt64LE",
                AnyLogicalArrayType::ArrayOfUInt16LE => "arrayOfUInt16LE",
                AnyLogicalArrayType::ArrayOfUInt32LE => "arrayOfUInt32LE",
                AnyLogicalArrayType::ArrayOfUInt64LE => "arrayOfUInt64LE",
                AnyLogicalArrayType::ArrayOfFloat32LE => "arrayOfFloat32LE",
                AnyLogicalArrayType::ArrayOfDouble64LE => "arrayOfDouble64LE",
                AnyLogicalArrayType::ArrayOfInt16BE => "arrayOfInt16BE",
                AnyLogicalArrayType::ArrayOfInt32BE => "arrayOfInt32BE",
                AnyLogicalArrayType::ArrayOfInt64BE => "arrayOfInt64BE",
                AnyLogicalArrayType::ArrayOfUInt16BE => "arrayOfUInt16BE",
                AnyLogicalArrayType::ArrayOfUInt32BE => "arrayOfUInt32BE",
                AnyLogicalArrayType::ArrayOfUInt64BE => "arrayOfUInt64BE",
                AnyLogicalArrayType::ArrayOfFloat32BE => "arrayOfFloat32BE",
                AnyLogicalArrayType::ArrayOfDouble64BE => "arrayOfDouble64BE",
                AnyLogicalArrayType::ArrayOfString => "arrayOfString",
                AnyLogicalArrayType::ArrayOfCustom => "arrayOfCustom",
            }
        )
    }
}

impl FromStr for AnyLogicalArrayType {
    type Err = ();
    fn from_str(input: &str) -> Result<AnyLogicalArrayType, Self::Err> {
        match input {
            "arrayOfBoolean" => Ok(AnyLogicalArrayType::ArrayOfBoolean),
            "arrayOfInt8" => Ok(AnyLogicalArrayType::ArrayOfInt8),
            "arrayOfUInt8" => Ok(AnyLogicalArrayType::ArrayOfUInt8),
            "arrayOfInt16LE" => Ok(AnyLogicalArrayType::ArrayOfInt16LE),
            "arrayOfInt32LE" => Ok(AnyLogicalArrayType::ArrayOfInt32LE),
            "arrayOfInt64LE" => Ok(AnyLogicalArrayType::ArrayOfInt64LE),
            "arrayOfUInt16LE" => Ok(AnyLogicalArrayType::ArrayOfUInt16LE),
            "arrayOfUInt32LE" => Ok(AnyLogicalArrayType::ArrayOfUInt32LE),
            "arrayOfUInt64LE" => Ok(AnyLogicalArrayType::ArrayOfUInt64LE),
            "arrayOfFloat32LE" => Ok(AnyLogicalArrayType::ArrayOfFloat32LE),
            "arrayOfDouble64LE" => Ok(AnyLogicalArrayType::ArrayOfDouble64LE),
            "arrayOfInt16BE" => Ok(AnyLogicalArrayType::ArrayOfInt16BE),
            "arrayOfInt32BE" => Ok(AnyLogicalArrayType::ArrayOfInt32BE),
            "arrayOfInt64BE" => Ok(AnyLogicalArrayType::ArrayOfInt64BE),
            "arrayOfUInt16BE" => Ok(AnyLogicalArrayType::ArrayOfUInt16BE),
            "arrayOfUInt32BE" => Ok(AnyLogicalArrayType::ArrayOfUInt32BE),
            "arrayOfUInt64BE" => Ok(AnyLogicalArrayType::ArrayOfUInt64BE),
            "arrayOfFloat32BE" => Ok(AnyLogicalArrayType::ArrayOfFloat32BE),
            "arrayOfDouble64BE" => Ok(AnyLogicalArrayType::ArrayOfDouble64BE),
            "arrayOfString" => Ok(AnyLogicalArrayType::ArrayOfString),
            "arrayOfCustom" => Ok(AnyLogicalArrayType::ArrayOfCustom),
            _ => Err(()),
        }
    }
}

impl AnyLogicalArrayType {
    pub fn iter() -> Iter<'static, AnyLogicalArrayType> {
        static VEC_ENUM: [AnyLogicalArrayType; 21] = [
            AnyLogicalArrayType::ArrayOfBoolean,
            AnyLogicalArrayType::ArrayOfInt8,
            AnyLogicalArrayType::ArrayOfUInt8,
            AnyLogicalArrayType::ArrayOfInt16LE,
            AnyLogicalArrayType::ArrayOfInt32LE,
            AnyLogicalArrayType::ArrayOfInt64LE,
            AnyLogicalArrayType::ArrayOfUInt16LE,
            AnyLogicalArrayType::ArrayOfUInt32LE,
            AnyLogicalArrayType::ArrayOfUInt64LE,
            AnyLogicalArrayType::ArrayOfFloat32LE,
            AnyLogicalArrayType::ArrayOfDouble64LE,
            AnyLogicalArrayType::ArrayOfInt16BE,
            AnyLogicalArrayType::ArrayOfInt32BE,
            AnyLogicalArrayType::ArrayOfInt64BE,
            AnyLogicalArrayType::ArrayOfUInt16BE,
            AnyLogicalArrayType::ArrayOfUInt32BE,
            AnyLogicalArrayType::ArrayOfUInt64BE,
            AnyLogicalArrayType::ArrayOfFloat32BE,
            AnyLogicalArrayType::ArrayOfDouble64BE,
            AnyLogicalArrayType::ArrayOfString,
            AnyLogicalArrayType::ArrayOfCustom,
        ];
        VEC_ENUM.iter()
    }
}
