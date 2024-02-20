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
pub struct DeleteParts {
    #[serde(rename = "uri")]
    pub uri: String,

    #[serde(rename = "uids")]
    pub uids: HashMap<String, String>,
}

fn deleteparts_avro_schema() -> Option<Schema> {
    match Schema::parse_str(AVRO_SCHEMA) {
        Ok(result) => Some(result),
        Err(e) => {
            panic!("{:?}", e);
        }
    }
}

impl Schemable for DeleteParts {
    fn avro_schema(&self) -> Option<Schema> {
        deleteparts_avro_schema()
    }
    fn avro_schema_str(&self) -> &'static str {
        AVRO_SCHEMA
    }
}

impl AvroSerializable for DeleteParts {}

impl AvroDeserializable for DeleteParts {
    fn avro_deserialize<R: Read>(input: &mut R) -> AvroResult<DeleteParts> {
        let record = from_avro_datum(&deleteparts_avro_schema().unwrap(), input, None).unwrap();
        from_value::<DeleteParts>(&record)
    }
}

impl ETPMetadata for DeleteParts {
    fn protocol(&self) -> i32 {
        6
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

impl DeleteParts {
    pub fn as_protocol_message(&self) -> ProtocolMessage {
        ProtocolMessage::GrowingObject_DeleteParts(self.clone())
    }
}

impl DeleteParts {
    /* Protocol 6, MessageType : 1 */
    pub fn default_with_params(uri: String) -> DeleteParts {
        DeleteParts {
            uri,
            uids: HashMap::new(),
        }
    }
}

pub static AVRO_SCHEMA: &'static str = r#"{
    "type": "record",
    "namespace": "Energistics.Etp.v12.Protocol.GrowingObject",
    "name": "DeleteParts",
    "protocol": "6",
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
            "name": "uids",
            "type": {
                "type": "map",
                "values": "string"
            }
        }
    ],
    "fullName": "Energistics.Etp.v12.Protocol.GrowingObject.DeleteParts",
    "depends": []
}"#;
