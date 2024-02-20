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
pub struct StartTransaction {
    #[serde(rename = "readOnly")]
    pub read_only: bool,

    #[serde(rename = "message")]
    #[derivative(Default(value = r#"String::from("")"#))]
    pub message: String,

    #[serde(rename = "dataspaceUris")]
    #[derivative(Default(value = "Vec::new()"))]
    pub dataspace_uris: Vec<String>,
}

fn starttransaction_avro_schema() -> Option<Schema> {
    match Schema::parse_str(AVRO_SCHEMA) {
        Ok(result) => Some(result),
        Err(e) => {
            panic!("{:?}", e);
        }
    }
}

impl Schemable for StartTransaction {
    fn avro_schema(&self) -> Option<Schema> {
        starttransaction_avro_schema()
    }
    fn avro_schema_str(&self) -> &'static str {
        AVRO_SCHEMA
    }
}

impl AvroSerializable for StartTransaction {}

impl AvroDeserializable for StartTransaction {
    fn avro_deserialize<R: Read>(input: &mut R) -> AvroResult<StartTransaction> {
        let record =
            from_avro_datum(&starttransaction_avro_schema().unwrap(), input, None).unwrap();
        from_value::<StartTransaction>(&record)
    }
}

impl ETPMetadata for StartTransaction {
    fn protocol(&self) -> i32 {
        18
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

impl StartTransaction {
    pub fn as_protocol_message(&self) -> ProtocolMessage {
        ProtocolMessage::Transaction_StartTransaction(self.clone())
    }
}

impl Default for StartTransaction {
    /* Protocol 18, MessageType : 1 */
    fn default() -> StartTransaction {
        StartTransaction {
            read_only: true,
            message: "".to_string(),
            dataspace_uris: vec!["".to_string()],
        }
    }
}

pub static AVRO_SCHEMA: &'static str = r#"{
    "type": "record",
    "namespace": "Energistics.Etp.v12.Protocol.Transaction",
    "name": "StartTransaction",
    "protocol": "18",
    "messageType": "1",
    "senderRole": "customer",
    "protocolRoles": "store,customer",
    "multipartFlag": false,
    "fields": [
        {
            "name": "readOnly",
            "type": "boolean"
        },
        {
            "name": "message",
            "type": "string",
            "default": ""
        },
        {
            "name": "dataspaceUris",
            "type": {
                "type": "array",
                "items": "string"
            },
            "default": [
                ""
            ]
        }
    ],
    "fullName": "Energistics.Etp.v12.Protocol.Transaction.StartTransaction",
    "depends": []
}"#;
