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

use crate::helpers::ETPMetadata;
use crate::helpers::Schemable;
use crate::protocols::ProtocolMessage;
use apache_avro::{from_avro_datum, from_value, AvroResult};
use std::io::Read;
#[derive(Debug, PartialEq, Clone, serde::Deserialize, serde::Serialize, Derivative)]
#[serde(rename_all = "PascalCase")]
pub struct DeletePartsResponse {
    #[serde(rename = "success")]
    pub success: HashMap<String, String>,
}

fn deletepartsresponse_avro_schema() -> Option<Schema> {
    match Schema::parse_str(AVRO_SCHEMA) {
        Ok(result) => Some(result),
        Err(e) => {
            panic!("{:?}", e);
        }
    }
}

impl Schemable for DeletePartsResponse {
    fn avro_schema(&self) -> Option<Schema> {
        deletepartsresponse_avro_schema()
    }
    fn avro_schema_str(&self) -> &'static str {
        AVRO_SCHEMA
    }
}

impl AvroSerializable for DeletePartsResponse {}

impl AvroDeserializable for DeletePartsResponse {
    fn avro_deserialize<R: Read>(input: &mut R) -> AvroResult<DeletePartsResponse> {
        let record =
            from_avro_datum(&deletepartsresponse_avro_schema().unwrap(), input, None).unwrap();
        from_value::<DeletePartsResponse>(&record)
    }
}

impl ETPMetadata for DeletePartsResponse {
    fn protocol(&self) -> i32 {
        6
    }
    fn message_type(&self) -> i32 {
        11
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

impl DeletePartsResponse {
    pub fn as_protocol_message(&self) -> ProtocolMessage {
        ProtocolMessage::GrowingObject_DeletePartsResponse(self.clone())
    }
}

impl Default for DeletePartsResponse {
    /* Protocol 6, MessageType : 11 */
    fn default() -> DeletePartsResponse {
        DeletePartsResponse {
            success: HashMap::new(),
        }
    }
}

pub static AVRO_SCHEMA: &'static str = r#"{
    "type": "record",
    "namespace": "Energistics.Etp.v12.Protocol.GrowingObject",
    "name": "DeletePartsResponse",
    "protocol": "6",
    "messageType": "11",
    "senderRole": "store",
    "protocolRoles": "store,customer",
    "multipartFlag": true,
    "fields": [
        {
            "name": "success",
            "type": {
                "type": "map",
                "values": "string"
            }
        }
    ],
    "fullName": "Energistics.Etp.v12.Protocol.GrowingObject.DeletePartsResponse",
    "depends": []
}"#;
