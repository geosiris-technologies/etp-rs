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

use crate::energistics::etp::v12::datatypes::object::index_interval::IndexInterval;
use crate::helpers::Schemable;
use apache_avro::{from_avro_datum, from_value, AvroResult};
use std::io::Read;

#[derive(Debug, PartialEq, Clone, serde::Deserialize, serde::Serialize, Derivative)]
#[serde(rename_all = "PascalCase")]
pub struct ChannelRangeInfo {
    #[serde(rename = "channelIds")]
    pub channel_ids: Vec<i64>,

    #[serde(rename = "interval")]
    pub interval: IndexInterval,

    #[serde(rename = "secondaryIntervals")]
    #[derivative(Default(value = "Vec::new()"))]
    pub secondary_intervals: Vec<IndexInterval>,
}

fn channelrangeinfo_avro_schema() -> Option<Schema> {
    match Schema::parse_str(AVRO_SCHEMA) {
        Ok(result) => Some(result),
        Err(e) => {
            panic!("{:?}", e);
        }
    }
}

impl Schemable for ChannelRangeInfo {
    fn avro_schema(&self) -> Option<Schema> {
        channelrangeinfo_avro_schema()
    }
    fn avro_schema_str(&self) -> &'static str {
        AVRO_SCHEMA
    }
}

impl AvroSerializable for ChannelRangeInfo {}

impl AvroDeserializable for ChannelRangeInfo {
    fn avro_deserialize<R: Read>(input: &mut R) -> AvroResult<ChannelRangeInfo> {
        let record =
            from_avro_datum(&channelrangeinfo_avro_schema().unwrap(), input, None).unwrap();
        from_value::<ChannelRangeInfo>(&record)
    }
}

impl ChannelRangeInfo {
    /* Protocol , MessageType :  */
    pub fn default_with_params(interval: IndexInterval) -> ChannelRangeInfo {
        ChannelRangeInfo {
            channel_ids: vec![],
            interval,
            secondary_intervals: vec![],
        }
    }
}

pub static AVRO_SCHEMA: &'static str = r#"{
    "type": "record",
    "namespace": "Energistics.Etp.v12.Datatypes.ChannelData",
    "name": "ChannelRangeInfo",
    "fields": [
        {
            "name": "channelIds",
            "type": {
                "type": "array",
                "items": "long"
            }
        },
        {
            "name": "interval",
            "type": {
                "type": "record",
                "namespace": "Energistics.Etp.v12.Datatypes.Object",
                "name": "IndexInterval",
                "fields": [
                    {
                        "name": "startIndex",
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
                    },
                    {
                        "name": "endIndex",
                        "type": "Energistics.Etp.v12.Datatypes.IndexValue"
                    },
                    {
                        "name": "uom",
                        "type": "string"
                    },
                    {
                        "name": "depthDatum",
                        "type": "string",
                        "default": ""
                    }
                ],
                "fullName": "Energistics.Etp.v12.Datatypes.Object.IndexInterval",
                "depends": [
                    "Energistics.Etp.v12.Datatypes.IndexValue"
                ]
            }
        },
        {
            "name": "secondaryIntervals",
            "type": {
                "type": "array",
                "items": "Energistics.Etp.v12.Datatypes.Object.IndexInterval"
            },
            "default": []
        }
    ],
    "fullName": "Energistics.Etp.v12.Datatypes.ChannelData.ChannelRangeInfo",
    "depends": [
        "Energistics.Etp.v12.Datatypes.Object.IndexInterval"
    ]
}"#;
