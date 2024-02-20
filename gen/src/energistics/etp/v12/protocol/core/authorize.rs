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
pub struct Authorize {
    #[serde(rename = "authorization")]
    pub authorization: String,

    #[serde(rename = "supplementalAuthorization")]
    pub supplemental_authorization: HashMap<String, String>,
}

fn authorize_avro_schema() -> Option<Schema> {
    match Schema::parse_str(AVRO_SCHEMA) {
        Ok(result) => Some(result),
        Err(e) => {
            panic!("{:?}", e);
        }
    }
}

impl Schemable for Authorize {
    fn avro_schema(&self) -> Option<Schema> {
        authorize_avro_schema()
    }
    fn avro_schema_str(&self) -> &'static str {
        AVRO_SCHEMA
    }
}

impl AvroSerializable for Authorize {}

impl AvroDeserializable for Authorize {
    fn avro_deserialize<R: Read>(input: &mut R) -> AvroResult<Authorize> {
        let record = from_avro_datum(&authorize_avro_schema().unwrap(), input, None).unwrap();
        from_value::<Authorize>(&record)
    }
}

impl ETPMetadata for Authorize {
    fn protocol(&self) -> i32 {
        0
    }
    fn message_type(&self) -> i32 {
        6
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

impl Authorize {
    pub fn as_protocol_message(&self) -> ProtocolMessage {
        ProtocolMessage::Core_Authorize(self.clone())
    }
}

impl Default for Authorize {
    /* Protocol 0, MessageType : 6 */
    fn default() -> Authorize {
        Authorize {
            authorization: "".to_string(),
            supplemental_authorization: HashMap::new(),
        }
    }
}

pub static AVRO_SCHEMA: &'static str = r#"{
    "type": "record",
    "namespace": "Energistics.Etp.v12.Protocol.Core",
    "name": "Authorize",
    "protocol": "0",
    "messageType": "6",
    "senderRole": "client,server",
    "protocolRoles": "client, server",
    "multipartFlag": false,
    "fields": [
        {
            "name": "authorization",
            "type": "string"
        },
        {
            "name": "supplementalAuthorization",
            "type": {
                "type": "map",
                "values": "string"
            }
        }
    ],
    "fullName": "Energistics.Etp.v12.Protocol.Core.Authorize",
    "depends": []
}"#;
