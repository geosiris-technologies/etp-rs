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

use crate::energistics::etp::v12::datatypes::array_of_string::ArrayOfString;
use crate::helpers::ETPMetadata;
use crate::helpers::Schemable;
use crate::protocols::ProtocolMessage;
use apache_avro::{from_avro_datum, from_value, AvroResult};
use std::io::Read;

#[derive(Debug, PartialEq, Clone, serde::Deserialize, serde::Serialize, Derivative)]
#[serde(rename_all = "PascalCase")]
pub struct DeleteDataObjectsResponse {
    #[serde(rename = "deletedUris")]
    pub deleted_uris: HashMap<String, ArrayOfString>,
}

fn deletedataobjectsresponse_avro_schema() -> Option<Schema> {
    match Schema::parse_str(AVRO_SCHEMA) {
        Ok(result) => Some(result),
        Err(e) => {
            panic!("{:?}", e);
        }
    }
}

impl Schemable for DeleteDataObjectsResponse {
    fn avro_schema(&self) -> Option<Schema> {
        deletedataobjectsresponse_avro_schema()
    }
    fn avro_schema_str(&self) -> &'static str {
        AVRO_SCHEMA
    }
}

impl AvroSerializable for DeleteDataObjectsResponse {}

impl AvroDeserializable for DeleteDataObjectsResponse {
    fn avro_deserialize<R: Read>(input: &mut R) -> AvroResult<DeleteDataObjectsResponse> {
        let record = from_avro_datum(
            &deletedataobjectsresponse_avro_schema().unwrap(),
            input,
            None,
        )
        .unwrap();
        from_value::<DeleteDataObjectsResponse>(&record)
    }
}

impl ETPMetadata for DeleteDataObjectsResponse {
    fn protocol(&self) -> i32 {
        4
    }
    fn message_type(&self) -> i32 {
        10
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

impl DeleteDataObjectsResponse {
    pub fn as_protocol_message(&self) -> ProtocolMessage {
        ProtocolMessage::Store_DeleteDataObjectsResponse(self.clone())
    }
}

impl Default for DeleteDataObjectsResponse {
    /* Protocol 4, MessageType : 10 */
    fn default() -> DeleteDataObjectsResponse {
        DeleteDataObjectsResponse {
            deleted_uris: HashMap::new(),
        }
    }
}

pub static AVRO_SCHEMA: &'static str = r#"{
    "type": "record",
    "namespace": "Energistics.Etp.v12.Protocol.Store",
    "name": "DeleteDataObjectsResponse",
    "protocol": "4",
    "messageType": "10",
    "senderRole": "store",
    "protocolRoles": "store,customer",
    "multipartFlag": true,
    "fields": [
        {
            "name": "deletedUris",
            "type": {
                "type": "map",
                "values": {
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
                }
            }
        }
    ],
    "fullName": "Energistics.Etp.v12.Protocol.Store.DeleteDataObjectsResponse",
    "depends": [
        "Energistics.Etp.v12.Datatypes.ArrayOfString"
    ]
}"#;
