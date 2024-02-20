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
pub struct AuthorizeResponse {
    #[serde(rename = "success")]
    pub success: bool,

    #[serde(rename = "challenges")]
    pub challenges: Vec<String>,
}

fn authorizeresponse_avro_schema() -> Option<Schema> {
    match Schema::parse_str(AVRO_SCHEMA) {
        Ok(result) => Some(result),
        Err(e) => {
            panic!("{:?}", e);
        }
    }
}

impl Schemable for AuthorizeResponse {
    fn avro_schema(&self) -> Option<Schema> {
        authorizeresponse_avro_schema()
    }
    fn avro_schema_str(&self) -> &'static str {
        AVRO_SCHEMA
    }
}

impl AvroSerializable for AuthorizeResponse {}

impl AvroDeserializable for AuthorizeResponse {
    fn avro_deserialize<R: Read>(input: &mut R) -> AvroResult<AuthorizeResponse> {
        let record =
            from_avro_datum(&authorizeresponse_avro_schema().unwrap(), input, None).unwrap();
        from_value::<AuthorizeResponse>(&record)
    }
}

impl ETPMetadata for AuthorizeResponse {
    fn protocol(&self) -> i32 {
        0
    }
    fn message_type(&self) -> i32 {
        7
    }
    fn sender_role(&self) -> Vec<Role> {
        vec![Role::Client, Role::Server]
    }
    fn protocol_roles(&self) -> Vec<Role> {
        vec![Role::Client, Role::Server]
    }
    fn multipart_flag(&self) -> bool {
        false
    }
}

impl AuthorizeResponse {
    pub fn as_protocol_message(&self) -> ProtocolMessage {
        ProtocolMessage::Core_AuthorizeResponse(self.clone())
    }
}

impl Default for AuthorizeResponse {
    /* Protocol 0, MessageType : 7 */
    fn default() -> AuthorizeResponse {
        AuthorizeResponse {
            success: true,
            challenges: vec![],
        }
    }
}

pub static AVRO_SCHEMA: &'static str = r#"{
    "type": "record",
    "namespace": "Energistics.Etp.v12.Protocol.Core",
    "name": "AuthorizeResponse",
    "protocol": "0",
    "messageType": "7",
    "senderRole": "client,server",
    "protocolRoles": "client, server",
    "multipartFlag": false,
    "fields": [
        {
            "name": "success",
            "type": "boolean"
        },
        {
            "name": "challenges",
            "type": {
                "type": "array",
                "items": "string"
            }
        }
    ],
    "fullName": "Energistics.Etp.v12.Protocol.Core.AuthorizeResponse",
    "depends": []
}"#;
