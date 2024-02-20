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

use crate::energistics::etp::v12::datatypes::object::dataspace::Dataspace;
use crate::helpers::ETPMetadata;
use crate::helpers::Schemable;
use crate::protocols::ProtocolMessage;
use apache_avro::{from_avro_datum, from_value, AvroResult};
use std::io::Read;

#[derive(Debug, PartialEq, Clone, serde::Deserialize, serde::Serialize, Derivative)]
#[serde(rename_all = "PascalCase")]
pub struct GetDataspacesResponse {
    #[serde(rename = "dataspaces")]
    #[derivative(Default(value = "Vec::new()"))]
    pub dataspaces: Vec<Dataspace>,
}

fn getdataspacesresponse_avro_schema() -> Option<Schema> {
    match Schema::parse_str(AVRO_SCHEMA) {
        Ok(result) => Some(result),
        Err(e) => {
            panic!("{:?}", e);
        }
    }
}

impl Schemable for GetDataspacesResponse {
    fn avro_schema(&self) -> Option<Schema> {
        getdataspacesresponse_avro_schema()
    }
    fn avro_schema_str(&self) -> &'static str {
        AVRO_SCHEMA
    }
}

impl AvroSerializable for GetDataspacesResponse {}

impl AvroDeserializable for GetDataspacesResponse {
    fn avro_deserialize<R: Read>(input: &mut R) -> AvroResult<GetDataspacesResponse> {
        let record =
            from_avro_datum(&getdataspacesresponse_avro_schema().unwrap(), input, None).unwrap();
        from_value::<GetDataspacesResponse>(&record)
    }
}

impl ETPMetadata for GetDataspacesResponse {
    fn protocol(&self) -> i32 {
        24
    }
    fn message_type(&self) -> i32 {
        2
    }
    fn sender_role(&self) -> Vec<Role> {
        vec![Role::Store]
    }
    fn protocol_roles(&self) -> Vec<Role> {
        vec![Role::Store, Role::Customer]
    }
    fn multipart_flag(&self) -> bool {
        true
    }
}

impl GetDataspacesResponse {
    pub fn as_protocol_message(&self) -> ProtocolMessage {
        ProtocolMessage::Dataspace_GetDataspacesResponse(self.clone())
    }
}

impl Default for GetDataspacesResponse {
    /* Protocol 24, MessageType : 2 */
    fn default() -> GetDataspacesResponse {
        GetDataspacesResponse { dataspaces: vec![] }
    }
}

pub static AVRO_SCHEMA: &'static str = r#"{
    "type": "record",
    "namespace": "Energistics.Etp.v12.Protocol.Dataspace",
    "name": "GetDataspacesResponse",
    "protocol": "24",
    "messageType": "2",
    "senderRole": "store",
    "protocolRoles": "store,customer",
    "multipartFlag": true,
    "fields": [
        {
            "name": "dataspaces",
            "type": {
                "type": "array",
                "items": {
                    "type": "record",
                    "namespace": "Energistics.Etp.v12.Datatypes.Object",
                    "name": "Dataspace",
                    "fields": [
                        {
                            "name": "uri",
                            "type": "string"
                        },
                        {
                            "name": "path",
                            "type": "string",
                            "default": ""
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
                    "fullName": "Energistics.Etp.v12.Datatypes.Object.Dataspace",
                    "depends": [
                        "Energistics.Etp.v12.Datatypes.DataValue"
                    ]
                }
            },
            "default": []
        }
    ],
    "fullName": "Energistics.Etp.v12.Protocol.Dataspace.GetDataspacesResponse",
    "depends": [
        "Energistics.Etp.v12.Datatypes.Object.Dataspace"
    ]
}"#;
