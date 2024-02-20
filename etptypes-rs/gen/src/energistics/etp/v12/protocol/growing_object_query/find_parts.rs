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
pub struct FindParts {
    #[serde(rename = "uri")]
    pub uri: String,

    #[serde(rename = "format")]
    #[derivative(Default(value = r#"String::from("xml")"#))]
    pub format: String,
}

fn findparts_avro_schema() -> Option<Schema> {
    match Schema::parse_str(AVRO_SCHEMA) {
        Ok(result) => Some(result),
        Err(e) => {
            panic!("{:?}", e);
        }
    }
}

impl Schemable for FindParts {
    fn avro_schema(&self) -> Option<Schema> {
        findparts_avro_schema()
    }
    fn avro_schema_str(&self) -> &'static str {
        AVRO_SCHEMA
    }
}

impl AvroSerializable for FindParts {}

impl AvroDeserializable for FindParts {
    fn avro_deserialize<R: Read>(input: &mut R) -> AvroResult<FindParts> {
        let record = from_avro_datum(&findparts_avro_schema().unwrap(), input, None).unwrap();
        from_value::<FindParts>(&record)
    }
}

impl ETPMetadata for FindParts {
    fn protocol(&self) -> i32 {
        16
    }
    fn message_type(&self) -> i32 {
        1
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

impl FindParts {
    pub fn as_protocol_message(&self) -> ProtocolMessage {
        ProtocolMessage::GrowingObjectQuery_FindParts(self.clone())
    }
}

impl FindParts {
    /* Protocol 16, MessageType : 1 */
    pub fn default_with_params(uri: String) -> FindParts {
        FindParts {
            uri,
            format: "xml".to_string(),
        }
    }
}

pub static AVRO_SCHEMA: &'static str = r#"{
    "type": "record",
    "namespace": "Energistics.Etp.v12.Protocol.GrowingObjectQuery",
    "name": "FindParts",
    "protocol": "16",
    "messageType": "1",
    "senderRole": "customer",
    "protocolRoles": "store,customer",
    "multipartFlag": false,
    "fields": [
        {
            "name": "uri",
            "type": "string"
        },
        {
            "name": "format",
            "type": "string",
            "default": "xml"
        }
    ],
    "fullName": "Energistics.Etp.v12.Protocol.GrowingObjectQuery.FindParts",
    "depends": []
}"#;
