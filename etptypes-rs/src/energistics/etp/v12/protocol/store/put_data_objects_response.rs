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

use crate::energistics::etp::v12::datatypes::object::put_response::PutResponse;
use crate::helpers::ETPMetadata;
use crate::helpers::Schemable;
use crate::protocols::ProtocolMessage;
use apache_avro::{from_avro_datum, from_value, AvroResult};
use std::io::Read;

#[derive(Debug, PartialEq, Clone, serde::Deserialize, serde::Serialize, Derivative)]
#[serde(rename_all = "PascalCase")]
pub struct PutDataObjectsResponse {
    #[serde(rename = "success")]
    pub success: HashMap<String, PutResponse>,
}

fn putdataobjectsresponse_avro_schema() -> Option<Schema> {
    match Schema::parse_str(AVRO_SCHEMA) {
        Ok(result) => Some(result),
        Err(e) => {
            panic!("{:?}", e);
        }
    }
}

impl Schemable for PutDataObjectsResponse {
    fn avro_schema(&self) -> Option<Schema> {
        putdataobjectsresponse_avro_schema()
    }
    fn avro_schema_str(&self) -> &'static str {
        AVRO_SCHEMA
    }
}

impl AvroSerializable for PutDataObjectsResponse {}

impl AvroDeserializable for PutDataObjectsResponse {
    fn avro_deserialize<R: Read>(input: &mut R) -> AvroResult<PutDataObjectsResponse> {
        let record =
            from_avro_datum(&putdataobjectsresponse_avro_schema().unwrap(), input, None).unwrap();
        from_value::<PutDataObjectsResponse>(&record)
    }
}

impl ETPMetadata for PutDataObjectsResponse {
    fn protocol(&self) -> i32 {
        4
    }
    fn message_type(&self) -> i32 {
        9
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

impl PutDataObjectsResponse {
    pub fn as_protocol_message(&self) -> ProtocolMessage {
        ProtocolMessage::Store_PutDataObjectsResponse(self.clone())
    }
}

impl Default for PutDataObjectsResponse {
    /* Protocol 4, MessageType : 9 */
    fn default() -> PutDataObjectsResponse {
        PutDataObjectsResponse {
            success: HashMap::new(),
        }
    }
}

pub static AVRO_SCHEMA: &'static str = r#"{
    "type": "record",
    "namespace": "Energistics.Etp.v12.Protocol.Store",
    "name": "PutDataObjectsResponse",
    "protocol": "4",
    "messageType": "9",
    "senderRole": "store",
    "protocolRoles": "store,customer",
    "multipartFlag": true,
    "fields": [
        {
            "name": "success",
            "type": {
                "type": "map",
                "values": {
                    "type": "record",
                    "namespace": "Energistics.Etp.v12.Datatypes.Object",
                    "name": "PutResponse",
                    "fields": [
                        {
                            "name": "createdContainedObjectUris",
                            "type": {
                                "type": "array",
                                "items": "string"
                            },
                            "default": []
                        },
                        {
                            "name": "deletedContainedObjectUris",
                            "type": {
                                "type": "array",
                                "items": "string"
                            },
                            "default": []
                        },
                        {
                            "name": "joinedContainedObjectUris",
                            "type": {
                                "type": "array",
                                "items": "string"
                            },
                            "default": []
                        },
                        {
                            "name": "unjoinedContainedObjectUris",
                            "type": {
                                "type": "array",
                                "items": "string"
                            },
                            "default": []
                        }
                    ],
                    "fullName": "Energistics.Etp.v12.Datatypes.Object.PutResponse",
                    "depends": []
                }
            }
        }
    ],
    "fullName": "Energistics.Etp.v12.Protocol.Store.PutDataObjectsResponse",
    "depends": [
        "Energistics.Etp.v12.Datatypes.Object.PutResponse"
    ]
}"#;
