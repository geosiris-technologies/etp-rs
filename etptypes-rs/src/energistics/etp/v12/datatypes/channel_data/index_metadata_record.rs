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

use crate::energistics::etp::v12::datatypes::channel_data::channel_index_kind::ChannelIndexKind;
use crate::energistics::etp::v12::datatypes::channel_data::index_direction::IndexDirection;
use crate::energistics::etp::v12::datatypes::object::index_interval::IndexInterval;
use crate::helpers::Schemable;
use apache_avro::{from_avro_datum, from_value, AvroResult};
use std::io::Read;

#[derive(Debug, PartialEq, Clone, serde::Deserialize, serde::Serialize, Derivative)]
#[serde(rename_all = "PascalCase")]
pub struct IndexMetadataRecord {
    #[serde(rename = "indexKind")]
    pub index_kind: ChannelIndexKind,

    #[serde(rename = "interval")]
    pub interval: IndexInterval,

    #[serde(rename = "direction")]
    pub direction: IndexDirection,

    #[serde(rename = "name")]
    #[derivative(Default(value = r#"String::from("")"#))]
    pub name: String,

    #[serde(rename = "uom")]
    pub uom: String,

    #[serde(rename = "depthDatum")]
    #[derivative(Default(value = r#"String::from("")"#))]
    pub depth_datum: String,

    #[serde(rename = "indexPropertyKindUri")]
    pub index_property_kind_uri: String,

    #[serde(rename = "filterable")]
    #[derivative(Default(value = "true"))]
    pub filterable: bool,
}

fn indexmetadatarecord_avro_schema() -> Option<Schema> {
    match Schema::parse_str(AVRO_SCHEMA) {
        Ok(result) => Some(result),
        Err(e) => {
            panic!("{:?}", e);
        }
    }
}

impl Schemable for IndexMetadataRecord {
    fn avro_schema(&self) -> Option<Schema> {
        indexmetadatarecord_avro_schema()
    }
    fn avro_schema_str(&self) -> &'static str {
        AVRO_SCHEMA
    }
}

impl AvroSerializable for IndexMetadataRecord {}

impl AvroDeserializable for IndexMetadataRecord {
    fn avro_deserialize<R: Read>(input: &mut R) -> AvroResult<IndexMetadataRecord> {
        let record =
            from_avro_datum(&indexmetadatarecord_avro_schema().unwrap(), input, None).unwrap();
        from_value::<IndexMetadataRecord>(&record)
    }
}

impl IndexMetadataRecord {
    /* Protocol , MessageType :  */
    pub fn default_with_params(
        index_kind: ChannelIndexKind,
        interval: IndexInterval,
        direction: IndexDirection,
    ) -> IndexMetadataRecord {
        IndexMetadataRecord {
            index_kind,
            interval,
            direction,
            name: "".to_string(),
            uom: "".to_string(),
            depth_datum: "".to_string(),
            index_property_kind_uri: "".to_string(),
            filterable: true,
        }
    }
}

pub static AVRO_SCHEMA: &'static str = r#"{
    "type": "record",
    "namespace": "Energistics.Etp.v12.Datatypes.ChannelData",
    "name": "IndexMetadataRecord",
    "fields": [
        {
            "name": "indexKind",
            "type": {
                "type": "enum",
                "namespace": "Energistics.Etp.v12.Datatypes.ChannelData",
                "name": "ChannelIndexKind",
                "symbols": [
                    "DateTime",
                    "ElapsedTime",
                    "MeasuredDepth",
                    "TrueVerticalDepth",
                    "PassIndexedDepth",
                    "Pressure",
                    "Temperature",
                    "Scalar"
                ],
                "fullName": "Energistics.Etp.v12.Datatypes.ChannelData.ChannelIndexKind",
                "depends": []
            },
            "default": "DateTime"
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
            "name": "direction",
            "type": {
                "type": "enum",
                "namespace": "Energistics.Etp.v12.Datatypes.ChannelData",
                "name": "IndexDirection",
                "symbols": [
                    "Increasing",
                    "Decreasing",
                    "Unordered"
                ],
                "fullName": "Energistics.Etp.v12.Datatypes.ChannelData.IndexDirection",
                "depends": []
            },
            "default": "Increasing"
        },
        {
            "name": "name",
            "type": "string",
            "default": ""
        },
        {
            "name": "uom",
            "type": "string"
        },
        {
            "name": "depthDatum",
            "type": "string",
            "default": ""
        },
        {
            "name": "indexPropertyKindUri",
            "type": "string"
        },
        {
            "name": "filterable",
            "type": "boolean",
            "default": true
        }
    ],
    "fullName": "Energistics.Etp.v12.Datatypes.ChannelData.IndexMetadataRecord",
    "depends": [
        "Energistics.Etp.v12.Datatypes.ChannelData.ChannelIndexKind",
        "Energistics.Etp.v12.Datatypes.Object.IndexInterval",
        "Energistics.Etp.v12.Datatypes.ChannelData.IndexDirection"
    ]
}"#;
