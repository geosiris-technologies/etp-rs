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
pub struct DeleteDataspaces {
    #[serde(rename = "uris")]
    pub uris: HashMap<String, String>,
}

fn deletedataspaces_avro_schema() -> Option<Schema> {
    match Schema::parse_str(AVRO_SCHEMA) {
        Ok(result) => Some(result),
        Err(e) => {
            panic!("{:?}", e);
        }
    }
}

impl Schemable for DeleteDataspaces {
    fn avro_schema(&self) -> Option<Schema> {
        deletedataspaces_avro_schema()
    }
    fn avro_schema_str(&self) -> &'static str {
        AVRO_SCHEMA
    }
}

impl AvroSerializable for DeleteDataspaces {}

impl AvroDeserializable for DeleteDataspaces {
    fn avro_deserialize<R: Read>(input: &mut R) -> AvroResult<DeleteDataspaces> {
        let record =
            from_avro_datum(&deletedataspaces_avro_schema().unwrap(), input, None).unwrap();
        from_value::<DeleteDataspaces>(&record)
    }
}

impl ETPMetadata for DeleteDataspaces {
    fn protocol(&self) -> i32 {
        24
    }
    fn message_type(&self) -> i32 {
        4
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

impl DeleteDataspaces {
    pub fn as_protocol_message(&self) -> ProtocolMessage {
        ProtocolMessage::Dataspace_DeleteDataspaces(self.clone())
    }
}

impl Default for DeleteDataspaces {
    /* Protocol 24, MessageType : 4 */
    fn default() -> DeleteDataspaces {
        DeleteDataspaces {
            uris: HashMap::new(),
        }
    }
}

pub static AVRO_SCHEMA: &'static str = r#"{
    "type": "record",
    "namespace": "Energistics.Etp.v12.Protocol.Dataspace",
    "name": "DeleteDataspaces",
    "protocol": "24",
    "messageType": "4",
    "senderRole": "customer",
    "protocolRoles": "store,customer",
    "multipartFlag": false,
    "fields": [
        {
            "name": "uris",
            "type": {
                "type": "map",
                "values": "string"
            }
        }
    ],
    "fullName": "Energistics.Etp.v12.Protocol.Dataspace.DeleteDataspaces",
    "depends": []
}"#;
