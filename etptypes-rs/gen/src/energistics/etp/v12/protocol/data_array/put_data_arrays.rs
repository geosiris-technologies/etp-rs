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

use crate::energistics::etp::v12::datatypes::data_array_types::put_data_arrays_type::PutDataArraysType;
use crate::helpers::ETPMetadata;
use crate::helpers::Schemable;
use crate::protocols::ProtocolMessage;
use apache_avro::{from_avro_datum, from_value, AvroResult};
use std::io::Read;

#[derive(Debug, PartialEq, Clone, serde::Deserialize, serde::Serialize, Derivative)]
#[serde(rename_all = "PascalCase")]
pub struct PutDataArrays {
    #[serde(rename = "dataArrays")]
    pub data_arrays: HashMap<String, PutDataArraysType>,
}

fn putdataarrays_avro_schema() -> Option<Schema> {
    match Schema::parse_str(AVRO_SCHEMA) {
        Ok(result) => Some(result),
        Err(e) => {
            panic!("{:?}", e);
        }
    }
}

impl Schemable for PutDataArrays {
    fn avro_schema(&self) -> Option<Schema> {
        putdataarrays_avro_schema()
    }
    fn avro_schema_str(&self) -> &'static str {
        AVRO_SCHEMA
    }
}

impl AvroSerializable for PutDataArrays {}

impl AvroDeserializable for PutDataArrays {
    fn avro_deserialize<R: Read>(input: &mut R) -> AvroResult<PutDataArrays> {
        let record = from_avro_datum(&putdataarrays_avro_schema().unwrap(), input, None).unwrap();
        from_value::<PutDataArrays>(&record)
    }
}

impl ETPMetadata for PutDataArrays {
    fn protocol(&self) -> i32 {
        9
    }
    fn message_type(&self) -> i32 {
        4
    }
    fn sender_role(&self) -> Vec<Role> {
        vec![Role::Customer]
    }
    fn protocol_roles(&self) -> Vec<Role> {
        vec![Role::Store, Role::Customer]
    }
    fn multipart_flag(&self) -> bool {
        false
    }
}

impl PutDataArrays {
    pub fn as_protocol_message(&self) -> ProtocolMessage {
        ProtocolMessage::DataArray_PutDataArrays(self.clone())
    }
}

impl Default for PutDataArrays {
    /* Protocol 9, MessageType : 4 */
    fn default() -> PutDataArrays {
        PutDataArrays {
            data_arrays: HashMap::new(),
        }
    }
}

pub static AVRO_SCHEMA: &'static str = r#"{
    "type": "record",
    "namespace": "Energistics.Etp.v12.Protocol.DataArray",
    "name": "PutDataArrays",
    "protocol": "9",
    "messageType": "4",
    "senderRole": "customer",
    "protocolRoles": "store,customer",
    "multipartFlag": false,
    "fields": [
        {
            "name": "dataArrays",
            "type": {
                "type": "map",
                "values": {
                    "type": "record",
                    "namespace": "Energistics.Etp.v12.Datatypes.DataArrayTypes",
                    "name": "PutDataArraysType",
                    "fields": [
                        {
                            "name": "uid",
                            "type": {
                                "type": "record",
                                "namespace": "Energistics.Etp.v12.Datatypes.DataArrayTypes",
                                "name": "DataArrayIdentifier",
                                "fields": [
                                    {
                                        "name": "uri",
                                        "type": "string"
                                    },
                                    {
                                        "name": "pathInResource",
                                        "type": "string"
                                    }
                                ],
                                "fullName": "Energistics.Etp.v12.Datatypes.DataArrayTypes.DataArrayIdentifier",
                                "depends": []
                            }
                        },
                        {
                            "name": "array",
                            "type": {
                                "type": "record",
                                "namespace": "Energistics.Etp.v12.Datatypes.DataArrayTypes",
                                "name": "DataArray",
                                "fields": [
                                    {
                                        "name": "dimensions",
                                        "type": {
                                            "type": "array",
                                            "items": "long"
                                        }
                                    },
                                    {
                                        "name": "data",
                                        "type": {
                                            "type": "record",
                                            "namespace": "Energistics.Etp.v12.Datatypes",
                                            "name": "AnyArray",
                                            "fields": [
                                                {
                                                    "name": "item",
                                                    "type": [
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
                                "fullName": "Energistics.Etp.v12.Datatypes.DataArrayTypes.DataArray",
                                "depends": [
                                    "Energistics.Etp.v12.Datatypes.AnyArray"
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
                                                "Energistics.Etp.v12.Datatypes.ArrayOfBoolean",
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
                                                "Energistics.Etp.v12.Datatypes.ArrayOfInt",
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
                                                "Energistics.Etp.v12.Datatypes.ArrayOfLong",
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
                                                "Energistics.Etp.v12.Datatypes.ArrayOfFloat",
                                                "Energistics.Etp.v12.Datatypes.ArrayOfDouble",
                                                "Energistics.Etp.v12.Datatypes.ArrayOfString",
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
                                                                            "type": "Energistics.Etp.v12.Datatypes.AnyArray"
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
                    "fullName": "Energistics.Etp.v12.Datatypes.DataArrayTypes.PutDataArraysType",
                    "depends": [
                        "Energistics.Etp.v12.Datatypes.DataArrayTypes.DataArrayIdentifier",
                        "Energistics.Etp.v12.Datatypes.DataArrayTypes.DataArray",
                        "Energistics.Etp.v12.Datatypes.DataValue"
                    ]
                }
            }
        }
    ],
    "fullName": "Energistics.Etp.v12.Protocol.DataArray.PutDataArrays",
    "depends": [
        "Energistics.Etp.v12.Datatypes.DataArrayTypes.PutDataArraysType"
    ]
}"#;
