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

use crate::energistics::etp::v12::datatypes::object::object_part::ObjectPart;
use crate::helpers::ETPMetadata;
use crate::helpers::Schemable;
use crate::protocols::ProtocolMessage;
use apache_avro::{from_avro_datum, from_value, AvroResult};
use std::io::Read;

#[derive(Debug, PartialEq, Clone, serde::Deserialize, serde::Serialize, Derivative)]
#[serde(rename_all = "PascalCase")]
pub struct PutParts {
    #[serde(rename = "uri")]
    pub uri: String,

    #[serde(rename = "format")]
    #[derivative(Default(value = r#"String::from("xml")"#))]
    pub format: String,

    #[serde(rename = "parts")]
    pub parts: HashMap<String, ObjectPart>,
}

fn putparts_avro_schema() -> Option<Schema> {
    match Schema::parse_str(AVRO_SCHEMA) {
        Ok(result) => Some(result),
        Err(e) => {
            panic!("{:?}", e);
        }
    }
}

impl Schemable for PutParts {
    fn avro_schema(&self) -> Option<Schema> {
        putparts_avro_schema()
    }
    fn avro_schema_str(&self) -> &'static str {
        AVRO_SCHEMA
    }
}

impl AvroSerializable for PutParts {}

impl AvroDeserializable for PutParts {
    fn avro_deserialize<R: Read>(input: &mut R) -> AvroResult<PutParts> {
        let record = from_avro_datum(&putparts_avro_schema().unwrap(), input, None).unwrap();
        from_value::<PutParts>(&record)
    }
}

impl ETPMetadata for PutParts {
    fn protocol(&self) -> i32 {
        6
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

impl PutParts {
    pub fn as_protocol_message(&self) -> ProtocolMessage {
        ProtocolMessage::GrowingObject_PutParts(self.clone())
    }
}

impl PutParts {
    /* Protocol 6, MessageType : 5 */
    pub fn default_with_params(uri: String) -> PutParts {
        PutParts {
            uri,
            format: "xml".to_string(),
            parts: HashMap::new(),
        }
    }
}

pub static AVRO_SCHEMA: &'static str = r#"{
    "type": "record",
    "namespace": "Energistics.Etp.v12.Protocol.GrowingObject",
    "name": "PutParts",
    "protocol": "6",
    "messageType": "5",
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
        },
        {
            "name": "parts",
            "type": {
                "type": "map",
                "values": {
                    "type": "record",
                    "namespace": "Energistics.Etp.v12.Datatypes.Object",
                    "name": "ObjectPart",
                    "fields": [
                        {
                            "name": "uid",
                            "type": "string"
                        },
                        {
                            "name": "data",
                            "type": "bytes"
                        }
                    ],
                    "fullName": "Energistics.Etp.v12.Datatypes.Object.ObjectPart",
                    "depends": []
                }
            }
        }
    ],
    "fullName": "Energistics.Etp.v12.Protocol.GrowingObject.PutParts",
    "depends": [
        "Energistics.Etp.v12.Datatypes.Object.ObjectPart"
    ]
}"#;
