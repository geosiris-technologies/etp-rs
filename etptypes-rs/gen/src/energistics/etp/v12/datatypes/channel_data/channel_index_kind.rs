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
pub enum ChannelIndexKind {
    /* None */
    #[serde(rename(serialize = "DateTime", deserialize = "DateTime"))]
    DateTime,
    #[serde(rename(serialize = "ElapsedTime", deserialize = "ElapsedTime"))]
    ElapsedTime,
    #[serde(rename(serialize = "MeasuredDepth", deserialize = "MeasuredDepth"))]
    MeasuredDepth,
    #[serde(rename(serialize = "TrueVerticalDepth", deserialize = "TrueVerticalDepth"))]
    TrueVerticalDepth,
    #[serde(rename(serialize = "PassIndexedDepth", deserialize = "PassIndexedDepth"))]
    PassIndexedDepth,
    #[serde(rename(serialize = "Pressure", deserialize = "Pressure"))]
    Pressure,
    #[serde(rename(serialize = "Temperature", deserialize = "Temperature"))]
    Temperature,
    #[serde(rename(serialize = "Scalar", deserialize = "Scalar"))]
    Scalar,
}

impl fmt::Display for ChannelIndexKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                ChannelIndexKind::DateTime => "DateTime",
                ChannelIndexKind::ElapsedTime => "ElapsedTime",
                ChannelIndexKind::MeasuredDepth => "MeasuredDepth",
                ChannelIndexKind::TrueVerticalDepth => "TrueVerticalDepth",
                ChannelIndexKind::PassIndexedDepth => "PassIndexedDepth",
                ChannelIndexKind::Pressure => "Pressure",
                ChannelIndexKind::Temperature => "Temperature",
                ChannelIndexKind::Scalar => "Scalar",
            }
        )
    }
}

impl FromStr for ChannelIndexKind {
    type Err = ();
    fn from_str(input: &str) -> Result<ChannelIndexKind, Self::Err> {
        match input {
            "DateTime" => Ok(ChannelIndexKind::DateTime),
            "ElapsedTime" => Ok(ChannelIndexKind::ElapsedTime),
            "MeasuredDepth" => Ok(ChannelIndexKind::MeasuredDepth),
            "TrueVerticalDepth" => Ok(ChannelIndexKind::TrueVerticalDepth),
            "PassIndexedDepth" => Ok(ChannelIndexKind::PassIndexedDepth),
            "Pressure" => Ok(ChannelIndexKind::Pressure),
            "Temperature" => Ok(ChannelIndexKind::Temperature),
            "Scalar" => Ok(ChannelIndexKind::Scalar),
            _ => Err(()),
        }
    }
}

impl ChannelIndexKind {
    pub fn iter() -> Iter<'static, ChannelIndexKind> {
        static VEC_ENUM: [ChannelIndexKind; 8] = [
            ChannelIndexKind::DateTime,
            ChannelIndexKind::ElapsedTime,
            ChannelIndexKind::MeasuredDepth,
            ChannelIndexKind::TrueVerticalDepth,
            ChannelIndexKind::PassIndexedDepth,
            ChannelIndexKind::Pressure,
            ChannelIndexKind::Temperature,
            ChannelIndexKind::Scalar,
        ];
        VEC_ENUM.iter()
    }
}
