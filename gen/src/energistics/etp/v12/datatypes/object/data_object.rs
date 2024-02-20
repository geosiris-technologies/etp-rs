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

use crate::energistics::etp::v12::datatypes::object::resource::Resource;
use crate::energistics::etp::v12::datatypes::uuid::{random_uuid, Uuid};
use crate::helpers::Schemable;
use apache_avro::{from_avro_datum, from_value, AvroResult};
use std::io::Read;

#[derive(Debug, PartialEq, Clone, serde::Deserialize, serde::Serialize, Derivative)]
#[serde(rename_all = "PascalCase")]
pub struct DataObject {
    #[serde(rename = "resource")]
    pub resource: Resource,

    #[serde(rename = "format")]
    #[derivative(Default(value = r#"String::from("xml")"#))]
    pub format: String,

    #[serde(with = "serde_bytes")]
    #[serde(rename = "blobId")]
    pub blob_id: Option<Uuid>,

    #[serde(with = "serde_bytes")]
    #[serde(rename = "data")]
    #[derivative(Default(value = ""))]
    pub data: Vec<u8>,
}

fn dataobject_avro_schema() -> Option<Schema> {
    match Schema::parse_str(AVRO_SCHEMA) {
        Ok(result) => Some(result),
        Err(e) => {
            panic!("{:?}", e);
        }
    }
}

impl Schemable for DataObject {
    fn avro_schema(&self) -> Option<Schema> {
        dataobject_avro_schema()
    }
    fn avro_schema_str(&self) -> &'static str {
        AVRO_SCHEMA
    }
}

impl AvroSerializable for DataObject {}

impl AvroDeserializable for DataObject {
    fn avro_deserialize<R: Read>(input: &mut R) -> AvroResult<DataObject> {
        let record = from_avro_datum(&dataobject_avro_schema().unwrap(), input, None).unwrap();
        from_value::<DataObject>(&record)
    }
}

impl DataObject {
    /* Protocol , MessageType :  */
    pub fn default_with_params(
        resource: Resource,
        blob_id: Option<Uuid>,
        data: Vec<u8>,
    ) -> DataObject {
        DataObject {
            resource,
            format: "xml".to_string(),
            blob_id,
            data,
        }
    }
}

pub static AVRO_SCHEMA: &'static str = r#"{
    "type": "record",
    "namespace": "Energistics.Etp.v12.Datatypes.Object",
    "name": "DataObject",
    "fields": [
        {
            "name": "resource",
            "type": {
                "type": "record",
                "namespace": "Energistics.Etp.v12.Datatypes.Object",
                "name": "Resource",
                "fields": [
                    {
                        "name": "uri",
                        "type": "string"
                    },
                    {
                        "name": "alternateUris",
                        "type": {
                            "type": "array",
                            "items": "string"
                        },
                        "default": []
                    },
                    {
                        "name": "name",
                        "type": "string"
                    },
                    {
                        "name": "sourceCount",
                        "type": [
                            "null",
                            "int"
                        ],
                        "default": null
                    },
                    {
                        "name": "targetCount",
                        "type": [
                            "null",
                            "int"
                        ],
                        "default": null
                    },
                    {
                        "name": "lastChanged",
                        "type": "long"
                    },
                    {
                        "name": "storeLastWrite",
                        "type": "long"
                    },
                    {
                        "name": "storeCreated",
                        "type": "long"
                    },
                    {
                        "name": "activeStatus",
                        "type": {
                            "type": "enum",
                            "namespace": "Energistics.Etp.v12.Datatypes.Object",
                            "name": "ActiveStatusKind",
                            "symbols": [
                                "Active",
                                "Inactive"
                            ],
                            "fullName": "Energistics.Etp.v12.Datatypes.Object.ActiveStatusKind",
                            "depends": []
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
                "fullName": "Energistics.Etp.v12.Datatypes.Object.Resource",
                "depends": [
                    "Energistics.Etp.v12.Datatypes.Object.ActiveStatusKind",
                    "Energistics.Etp.v12.Datatypes.DataValue"
                ]
            }
        },
        {
            "name": "format",
            "type": "string",
            "default": "xml"
        },
        {
            "name": "blobId",
            "type": [
                "null",
                {
                    "type": "fixed",
                    "namespace": "Energistics.Etp.v12.Datatypes",
                    "name": "Uuid",
                    "size": 16,
                    "fullName": "Energistics.Etp.v12.Datatypes.Uuid",
                    "depends": []
                }
            ]
        },
        {
            "name": "data",
            "type": "bytes",
            "default": ""
        }
    ],
    "fullName": "Energistics.Etp.v12.Datatypes.Object.DataObject",
    "depends": [
        "Energistics.Etp.v12.Datatypes.Object.Resource",
        "Energistics.Etp.v12.Datatypes.Uuid"
    ]
}"#;
