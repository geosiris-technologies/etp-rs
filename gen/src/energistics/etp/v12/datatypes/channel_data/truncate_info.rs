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

use crate::energistics::etp::v12::datatypes::index_value::IndexValue;
use crate::helpers::Schemable;
use apache_avro::{from_avro_datum, from_value, AvroResult};
use std::io::Read;

#[derive(Debug, PartialEq, Clone, serde::Deserialize, serde::Serialize, Derivative)]
#[serde(rename_all = "PascalCase")]
pub struct TruncateInfo {
    #[serde(rename = "channelId")]
    pub channel_id: i64,

    #[serde(rename = "newEndIndex")]
    pub new_end_index: IndexValue,
}

fn truncateinfo_avro_schema() -> Option<Schema> {
    match Schema::parse_str(AVRO_SCHEMA) {
        Ok(result) => Some(result),
        Err(e) => {
            panic!("{:?}", e);
        }
    }
}

impl Schemable for TruncateInfo {
    fn avro_schema(&self) -> Option<Schema> {
        truncateinfo_avro_schema()
    }
    fn avro_schema_str(&self) -> &'static str {
        AVRO_SCHEMA
    }
}

impl AvroSerializable for TruncateInfo {}

impl AvroDeserializable for TruncateInfo {
    fn avro_deserialize<R: Read>(input: &mut R) -> AvroResult<TruncateInfo> {
        let record = from_avro_datum(&truncateinfo_avro_schema().unwrap(), input, None).unwrap();
        from_value::<TruncateInfo>(&record)
    }
}

pub static AVRO_SCHEMA: &'static str = r#"{
    "type": "record",
    "namespace": "Energistics.Etp.v12.Datatypes.ChannelData",
    "name": "TruncateInfo",
    "fields": [
        {
            "name": "channelId",
            "type": "long"
        },
        {
            "name": "newEndIndex",
            "type": {
                "type": "record",
                "namespace": "Energistics.Etp.v12.Datatypes",
                "name": "IndexValue",
                "fields": [
                    {
                        "name": "item",
                        "type": [
                            "null",
                            "long",
                            "double",
                            {
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
                            }
                        ]
                    }
                ],
                "fullName": "Energistics.Etp.v12.Datatypes.IndexValue",
                "depends": [
                    "Energistics.Etp.v12.Datatypes.ChannelData.PassIndexedDepth"
                ]
            }
        }
    ],
    "fullName": "Energistics.Etp.v12.Datatypes.ChannelData.TruncateInfo",
    "depends": [
        "Energistics.Etp.v12.Datatypes.IndexValue"
    ]
}"#;
