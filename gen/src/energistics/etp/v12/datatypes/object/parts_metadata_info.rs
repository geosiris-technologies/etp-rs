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

use crate::energistics::etp::v12::datatypes::channel_data::index_metadata_record::IndexMetadataRecord;
use crate::energistics::etp::v12::datatypes::data_value::DataValue;
use crate::helpers::Schemable;
use apache_avro::{from_avro_datum, from_value, AvroResult};
use std::io::Read;

#[derive(Debug, PartialEq, Clone, serde::Deserialize, serde::Serialize, Derivative)]
#[serde(rename_all = "PascalCase")]
pub struct PartsMetadataInfo {
    #[serde(rename = "uri")]
    pub uri: String,

    #[serde(rename = "name")]
    pub name: String,

    #[serde(rename = "index")]
    pub index: IndexMetadataRecord,

    #[serde(rename = "customData")]
    #[derivative(Default(value = "HashMap::new()"))]
    pub custom_data: HashMap<String, DataValue>,
}

fn partsmetadatainfo_avro_schema() -> Option<Schema> {
    match Schema::parse_str(AVRO_SCHEMA) {
        Ok(result) => Some(result),
        Err(e) => {
            panic!("{:?}", e);
        }
    }
}

impl Schemable for PartsMetadataInfo {
    fn avro_schema(&self) -> Option<Schema> {
        partsmetadatainfo_avro_schema()
    }
    fn avro_schema_str(&self) -> &'static str {
        AVRO_SCHEMA
    }
}

impl AvroSerializable for PartsMetadataInfo {}

impl AvroDeserializable for PartsMetadataInfo {
    fn avro_deserialize<R: Read>(input: &mut R) -> AvroResult<PartsMetadataInfo> {
        let record =
            from_avro_datum(&partsmetadatainfo_avro_schema().unwrap(), input, None).unwrap();
        from_value::<PartsMetadataInfo>(&record)
    }
}

impl PartsMetadataInfo {
    /* Protocol , MessageType :  */
    pub fn default_with_params(uri: String, index: IndexMetadataRecord) -> PartsMetadataInfo {
        PartsMetadataInfo {
            uri,
            name: "".to_string(),
            index,
            custom_data: HashMap::new(),
        }
    }
}

pub static AVRO_SCHEMA: &'static str = r#"{
    "type": "record",
    "namespace": "Energistics.Etp.v12.Datatypes.Object",
    "name": "PartsMetadataInfo",
    "fields": [
        {
            "name": "uri",
            "type": "string"
        },
        {
            "name": "name",
            "type": "string"
        },
        {
            "name": "index",
            "type": {
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
            }
        },
        {
            "name": "customData",
            "type": {
                "type": "map",
                "values": {
                    "type": "record",
                    "namespace": "Energistics.Etp.v12.Datatypes",
                    "name": "DataValue",
                    "fields": [
                        {
                            "name": "item",
                            "type": [
                                "null",
                                "boolean",
                                "int",
                                "long",
                                "float",
                                "double",
                                "string",
                                {
                                    "type": "record",
                                    "namespace": "Energistics.Etp.v12.Datatypes",
                                    "name": "ArrayOfBoolean",
                                    "fields": [
                                        {
                                            "name": "values",
                                            "type": {
                                                "type": "array",
                                                "items": "boolean"
                                            }
                                        }
                                    ],
                                    "fullName": "Energistics.Etp.v12.Datatypes.ArrayOfBoolean",
                                    "depends": []
                                },
                                {
                                    "type": "record",
                                    "namespace": "Energistics.Etp.v12.Datatypes",
                                    "name": "ArrayOfNullableBoolean",
                                    "fields": [
                                        {
                                            "name": "values",
                                            "type": {
                                                "type": "array",
                                                "items": [
                                                    "null",
                                                    "boolean"
                                                ]
                                            }
                                        }
                                    ],
                                    "fullName": "Energistics.Etp.v12.Datatypes.ArrayOfNullableBoolean",
                                    "depends": []
                                },
                                {
                                    "type": "record",
                                    "namespace": "Energistics.Etp.v12.Datatypes",
                                    "name": "ArrayOfInt",
                                    "fields": [
                                        {
                                            "name": "values",
                                            "type": {
                                                "type": "array",
                                                "items": "int"
                                            }
                                        }
                                    ],
                                    "fullName": "Energistics.Etp.v12.Datatypes.ArrayOfInt",
                                    "depends": []
                                },
                                {
                                    "type": "record",
                                    "namespace": "Energistics.Etp.v12.Datatypes",
                                    "name": "ArrayOfNullableInt",
                                    "fields": [
                                        {
                                            "name": "values",
                                            "type": {
                                                "type": "array",
                                                "items": [
                                                    "null",
                                                    "int"
                                                ]
                                            }
                                        }
                                    ],
                                    "fullName": "Energistics.Etp.v12.Datatypes.ArrayOfNullableInt",
                                    "depends": []
                                },
                                {
                                    "type": "record",
                                    "namespace": "Energistics.Etp.v12.Datatypes",
                                    "name": "ArrayOfLong",
                                    "fields": [
                                        {
                                            "name": "values",
                                            "type": {
                                                "type": "array",
                                                "items": "long"
                                            }
                                        }
                                    ],
                                    "fullName": "Energistics.Etp.v12.Datatypes.ArrayOfLong",
                                    "depends": []
                                },
                                {
                                    "type": "record",
                                    "namespace": "Energistics.Etp.v12.Datatypes",
                                    "name": "ArrayOfNullableLong",
                                    "fields": [
                                        {
                                            "name": "values",
                                            "type": {
                                                "type": "array",
                                                "items": [
                                                    "null",
                                                    "long"
                                                ]
                                            }
                                        }
                                    ],
                                    "fullName": "Energistics.Etp.v12.Datatypes.ArrayOfNullableLong",
                                    "depends": []
                                },
                                {
                                    "type": "record",
                                    "namespace": "Energistics.Etp.v12.Datatypes",
                                    "name": "ArrayOfFloat",
                                    "fields": [
                                        {
                                            "name": "values",
                                            "type": {
                                                "type": "array",
                                                "items": "float"
                                            }
                                        }
                                    ],
                                    "fullName": "Energistics.Etp.v12.Datatypes.ArrayOfFloat",
                                    "depends": []
                                },
                                {
                                    "type": "record",
                                    "namespace": "Energistics.Etp.v12.Datatypes",
                                    "name": "ArrayOfDouble",
                                    "fields": [
                                        {
                                            "name": "values",
                                            "type": {
                                                "type": "array",
                                                "items": "double"
                                            }
                                        }
                                    ],
                                    "fullName": "Energistics.Etp.v12.Datatypes.ArrayOfDouble",
                                    "depends": []
                                },
                                {
                                    "type": "record",
                                    "namespace": "Energistics.Etp.v12.Datatypes",
                                    "name": "ArrayOfString",
                                    "fields": [
                                        {
                                            "name": "values",
                                            "type": {
                                                "type": "array",
                                                "items": "string"
                                            }
                                        }
                                    ],
                                    "fullName": "Energistics.Etp.v12.Datatypes.ArrayOfString",
                                    "depends": []
                                },
                                {
                                    "type": "record",
                                    "namespace": "Energistics.Etp.v12.Datatypes",
                                    "name": "ArrayOfBytes",
                                    "fields": [
                                        {
                                            "name": "values",
                                            "type": {
                                                "type": "array",
                                                "items": "bytes"
                                            }
                                        }
                                    ],
                                    "fullName": "Energistics.Etp.v12.Datatypes.ArrayOfBytes",
                                    "depends": []
                                },
                                "bytes",
                                {
                                    "type": "record",
                                    "namespace": "Energistics.Etp.v12.Datatypes",
                                    "name": "AnySparseArray",
                                    "fields": [
                                        {
                                            "name": "slices",
                                            "type": {
                                                "type": "array",
                                                "items": {
                                                    "type": "record",
                                                    "namespace": "Energistics.Etp.v12.Datatypes",
                                                    "name": "AnySubarray",
                                                    "fields": [
                                                        {
                                                            "name": "start",
                                                            "type": "long"
                                                        },
                                                        {
                                                            "name": "slice",
                                                            "type": {
                                                                "type": "record",
                                                                "namespace": "Energistics.Etp.v12.Datatypes",
                                                                "name": "AnyArray",
                                                                "fields": [
                                                                    {
                                                                        "name": "item",
                                                                        "type": [
                                                                            "Energistics.Etp.v12.Datatypes.ArrayOfBoolean",
                                                                            "Energistics.Etp.v12.Datatypes.ArrayOfInt",
                                                                            "Energistics.Etp.v12.Datatypes.ArrayOfLong",
                                                                            "Energistics.Etp.v12.Datatypes.ArrayOfFloat",
                                                                            "Energistics.Etp.v12.Datatypes.ArrayOfDouble",
                                                                            "Energistics.Etp.v12.Datatypes.ArrayOfString",
                                                                            "bytes"
                                                                        ]
                                                                    }
                                                                ],
                                                                "fullName": "Energistics.Etp.v12.Datatypes.AnyArray",
                                                                "depends": [
                                                                    "Energistics.Etp.v12.Datatypes.ArrayOfBoolean",
                                                                    "Energistics.Etp.v12.Datatypes.ArrayOfInt",
                                                                    "Energistics.Etp.v12.Datatypes.ArrayOfLong",
                                                                    "Energistics.Etp.v12.Datatypes.ArrayOfFloat",
                                                                    "Energistics.Etp.v12.Datatypes.ArrayOfDouble",
                                                                    "Energistics.Etp.v12.Datatypes.ArrayOfString"
                                                                ]
                                                            }
                                                        }
                                                    ],
                                                    "fullName": "Energistics.Etp.v12.Datatypes.AnySubarray",
                                                    "depends": [
                                                        "Energistics.Etp.v12.Datatypes.AnyArray"
                                                    ]
                                                }
                                            }
                                        }
                                    ],
                                    "fullName": "Energistics.Etp.v12.Datatypes.AnySparseArray",
                                    "depends": [
                                        "Energistics.Etp.v12.Datatypes.AnySubarray"
                                    ]
                                }
                            ]
                        }
                    ],
                    "fullName": "Energistics.Etp.v12.Datatypes.DataValue",
                    "depends": [
                        "Energistics.Etp.v12.Datatypes.ArrayOfBoolean",
                        "Energistics.Etp.v12.Datatypes.ArrayOfNullableBoolean",
                        "Energistics.Etp.v12.Datatypes.ArrayOfInt",
                        "Energistics.Etp.v12.Datatypes.ArrayOfNullableInt",
                        "Energistics.Etp.v12.Datatypes.ArrayOfLong",
                        "Energistics.Etp.v12.Datatypes.ArrayOfNullableLong",
                        "Energistics.Etp.v12.Datatypes.ArrayOfFloat",
                        "Energistics.Etp.v12.Datatypes.ArrayOfDouble",
                        "Energistics.Etp.v12.Datatypes.ArrayOfString",
                        "Energistics.Etp.v12.Datatypes.ArrayOfBytes",
                        "Energistics.Etp.v12.Datatypes.AnySparseArray"
                    ]
                }
            },
            "default": {}
        }
    ],
    "fullName": "Energistics.Etp.v12.Datatypes.Object.PartsMetadataInfo",
    "depends": [
        "Energistics.Etp.v12.Datatypes.ChannelData.IndexMetadataRecord",
        "Energistics.Etp.v12.Datatypes.DataValue"
    ]
}"#;
