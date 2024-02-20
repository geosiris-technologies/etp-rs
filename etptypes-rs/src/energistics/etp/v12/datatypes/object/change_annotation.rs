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
pub struct ChangeAnnotation {
    #[serde(rename = "changeTime")]
    pub change_time: i64,

    #[serde(rename = "interval")]
    pub interval: IndexInterval,
}

fn changeannotation_avro_schema() -> Option<Schema> {
    match Schema::parse_str(AVRO_SCHEMA) {
        Ok(result) => Some(result),
        Err(e) => {
            panic!("{:?}", e);
        }
    }
}

impl Schemable for ChangeAnnotation {
    fn avro_schema(&self) -> Option<Schema> {
        changeannotation_avro_schema()
    }
    fn avro_schema_str(&self) -> &'static str {
        AVRO_SCHEMA
    }
}

impl AvroSerializable for ChangeAnnotation {}

impl AvroDeserializable for ChangeAnnotation {
    fn avro_deserialize<R: Read>(input: &mut R) -> AvroResult<ChangeAnnotation> {
        let record =
            from_avro_datum(&changeannotation_avro_schema().unwrap(), input, None).unwrap();
        from_value::<ChangeAnnotation>(&record)
    }
}

impl ChangeAnnotation {
    /* Protocol , MessageType :  */
    pub fn default_with_params(interval: IndexInterval) -> ChangeAnnotation {
        ChangeAnnotation {
            change_time: time_to_etp(SystemTime::now()),
            interval,
        }
    }
}

pub static AVRO_SCHEMA: &'static str = r#"{
    "type": "record",
    "namespace": "Energistics.Etp.v12.Datatypes.Object",
    "name": "ChangeAnnotation",
    "fields": [
        {
            "name": "changeTime",
            "type": "long"
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
        }
    ],
    "fullName": "Energistics.Etp.v12.Datatypes.Object.ChangeAnnotation",
    "depends": [
        "Energistics.Etp.v12.Datatypes.Object.IndexInterval"
    ]
}"#;
