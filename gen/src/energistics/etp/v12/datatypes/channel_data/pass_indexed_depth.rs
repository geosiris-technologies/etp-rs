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

use crate::energistics::etp::v12::datatypes::channel_data::pass_direction::PassDirection;
use crate::helpers::Schemable;
use apache_avro::{from_avro_datum, from_value, AvroResult};
use std::io::Read;

#[derive(Debug, PartialEq, Clone, serde::Deserialize, serde::Serialize, Derivative)]
#[serde(rename_all = "PascalCase")]
pub struct PassIndexedDepth {
    #[serde(rename = "pass")]
    pub pass: i64,

    #[serde(rename = "direction")]
    pub direction: PassDirection,

    #[serde(rename = "depth")]
    pub depth: f64,
}

fn passindexeddepth_avro_schema() -> Option<Schema> {
    match Schema::parse_str(AVRO_SCHEMA) {
        Ok(result) => Some(result),
        Err(e) => {
            panic!("{:?}", e);
        }
    }
}

impl Schemable for PassIndexedDepth {
    fn avro_schema(&self) -> Option<Schema> {
        passindexeddepth_avro_schema()
    }
    fn avro_schema_str(&self) -> &'static str {
        AVRO_SCHEMA
    }
}

impl AvroSerializable for PassIndexedDepth {}

impl AvroDeserializable for PassIndexedDepth {
    fn avro_deserialize<R: Read>(input: &mut R) -> AvroResult<PassIndexedDepth> {
        let record =
            from_avro_datum(&passindexeddepth_avro_schema().unwrap(), input, None).unwrap();
        from_value::<PassIndexedDepth>(&record)
    }
}

pub static AVRO_SCHEMA: &'static str = r#"{
    "type": "record",
    "namespace": "Energistics.Etp.v12.Datatypes.ChannelData",
    "name": "PassIndexedDepth",
    "fields": [
        {
            "name": "pass",
            "type": "long"
        },
        {
            "name": "direction",
            "type": {
                "type": "enum",
                "namespace": "Energistics.Etp.v12.Datatypes.ChannelData",
                "name": "PassDirection",
                "symbols": [
                    "Up",
                    "HoldingSteady",
                    "Down"
                ],
                "fullName": "Energistics.Etp.v12.Datatypes.ChannelData.PassDirection",
                "depends": []
            }
        },
        {
            "name": "depth",
            "type": "double"
        }
    ],
    "fullName": "Energistics.Etp.v12.Datatypes.ChannelData.PassIndexedDepth",
    "depends": [
        "Energistics.Etp.v12.Datatypes.ChannelData.PassDirection"
    ]
}"#;
