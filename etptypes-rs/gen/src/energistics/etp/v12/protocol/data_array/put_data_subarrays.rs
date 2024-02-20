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

use crate::energistics::etp::v12::datatypes::data_array_types::put_data_subarrays_type::PutDataSubarraysType;
use crate::helpers::ETPMetadata;
use crate::helpers::Schemable;
use crate::protocols::ProtocolMessage;
use apache_avro::{from_avro_datum, from_value, AvroResult};
use std::io::Read;

#[derive(Debug, PartialEq, Clone, serde::Deserialize, serde::Serialize, Derivative)]
#[serde(rename_all = "PascalCase")]
pub struct PutDataSubarrays {
    #[serde(rename = "dataSubarrays")]
    pub data_subarrays: HashMap<String, PutDataSubarraysType>,
}

fn putdatasubarrays_avro_schema() -> Option<Schema> {
    match Schema::parse_str(AVRO_SCHEMA) {
        Ok(result) => Some(result),
        Err(e) => {
            panic!("{:?}", e);
        }
    }
}

impl Schemable for PutDataSubarrays {
    fn avro_schema(&self) -> Option<Schema> {
        putdatasubarrays_avro_schema()
    }
    fn avro_schema_str(&self) -> &'static str {
        AVRO_SCHEMA
    }
}

impl AvroSerializable for PutDataSubarrays {}

impl AvroDeserializable for PutDataSubarrays {
    fn avro_deserialize<R: Read>(input: &mut R) -> AvroResult<PutDataSubarrays> {
        let record =
            from_avro_datum(&putdatasubarrays_avro_schema().unwrap(), input, None).unwrap();
        from_value::<PutDataSubarrays>(&record)
    }
}

impl ETPMetadata for PutDataSubarrays {
    fn protocol(&self) -> i32 {
        9
    }
    fn message_type(&self) -> i32 {
        5
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

impl PutDataSubarrays {
    pub fn as_protocol_message(&self) -> ProtocolMessage {
        ProtocolMessage::DataArray_PutDataSubarrays(self.clone())
    }
}

impl Default for PutDataSubarrays {
    /* Protocol 9, MessageType : 5 */
    fn default() -> PutDataSubarrays {
        PutDataSubarrays {
            data_subarrays: HashMap::new(),
        }
    }
}

pub static AVRO_SCHEMA: &'static str = r#"{
    "type": "record",
    "namespace": "Energistics.Etp.v12.Protocol.DataArray",
    "name": "PutDataSubarrays",
    "protocol": "9",
    "messageType": "5",
    "senderRole": "customer",
    "protocolRoles": "store,customer",
    "multipartFlag": false,
    "fields": [
        {
            "name": "dataSubarrays",
            "type": {
                "type": "map",
                "values": {
                    "type": "record",
                    "namespace": "Energistics.Etp.v12.Datatypes.DataArrayTypes",
                    "name": "PutDataSubarraysType",
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
                        },
                        {
                            "name": "starts",
                            "type": {
                                "type": "array",
                                "items": "long"
                            }
                        },
                        {
                            "name": "counts",
                            "type": {
                                "type": "array",
                                "items": "long"
                            }
                        }
                    ],
                    "fullName": "Energistics.Etp.v12.Datatypes.DataArrayTypes.PutDataSubarraysType",
                    "depends": [
                        "Energistics.Etp.v12.Datatypes.DataArrayTypes.DataArrayIdentifier",
                        "Energistics.Etp.v12.Datatypes.AnyArray"
                    ]
                }
            }
        }
    ],
    "fullName": "Energistics.Etp.v12.Protocol.DataArray.PutDataSubarrays",
    "depends": [
        "Energistics.Etp.v12.Datatypes.DataArrayTypes.PutDataSubarraysType"
    ]
}"#;
