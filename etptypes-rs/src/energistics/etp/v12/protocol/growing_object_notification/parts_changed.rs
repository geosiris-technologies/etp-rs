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

use crate::energistics::etp::v12::datatypes::object::object_change_kind::ObjectChangeKind;
use crate::energistics::etp::v12::datatypes::object::object_part::ObjectPart;
use crate::energistics::etp::v12::datatypes::uuid::{random_uuid, Uuid};
use crate::helpers::ETPMetadata;
use crate::helpers::Schemable;
use crate::protocols::ProtocolMessage;
use apache_avro::{from_avro_datum, from_value, AvroResult};
use std::io::Read;

#[derive(Debug, PartialEq, Clone, serde::Deserialize, serde::Serialize, Derivative)]
#[serde(rename_all = "PascalCase")]
pub struct PartsChanged {
    #[serde(rename = "uri")]
    pub uri: String,

    #[serde(with = "serde_bytes")]
    #[serde(rename = "requestUuid")]
    pub request_uuid: Uuid,

    #[serde(rename = "changeKind")]
    pub change_kind: ObjectChangeKind,

    #[serde(rename = "changeTime")]
    pub change_time: i64,

    #[serde(rename = "format")]
    #[derivative(Default(value = r#"String::from("")"#))]
    pub format: String,

    #[serde(rename = "parts")]
    pub parts: Vec<ObjectPart>,
}

fn partschanged_avro_schema() -> Option<Schema> {
    match Schema::parse_str(AVRO_SCHEMA) {
        Ok(result) => Some(result),
        Err(e) => {
            panic!("{:?}", e);
        }
    }
}

impl Schemable for PartsChanged {
    fn avro_schema(&self) -> Option<Schema> {
        partschanged_avro_schema()
    }
    fn avro_schema_str(&self) -> &'static str {
        AVRO_SCHEMA
    }
}

impl AvroSerializable for PartsChanged {}

impl AvroDeserializable for PartsChanged {
    fn avro_deserialize<R: Read>(input: &mut R) -> AvroResult<PartsChanged> {
        let record = from_avro_datum(&partschanged_avro_schema().unwrap(), input, None).unwrap();
        from_value::<PartsChanged>(&record)
    }
}

impl ETPMetadata for PartsChanged {
    fn protocol(&self) -> i32 {
        7
    }
    fn message_type(&self) -> i32 {
        2
    }
    fn sender_role(&self) -> Vec<Role> {
        vec![Role::Store]
    }
    fn protocol_roles(&self) -> Vec<Role> {
        vec![Role::Store, Role::Customer]
    }
    fn multipart_flag(&self) -> bool {
        false
    }
}

impl PartsChanged {
    pub fn as_protocol_message(&self) -> ProtocolMessage {
        ProtocolMessage::GrowingObjectNotification_PartsChanged(self.clone())
    }
}

impl PartsChanged {
    /* Protocol 7, MessageType : 2 */
    pub fn default_with_params(uri: String, change_kind: ObjectChangeKind) -> PartsChanged {
        PartsChanged {
            uri,
            request_uuid: random_uuid(),
            change_kind,
            change_time: time_to_etp(SystemTime::now()),
            format: "".to_string(),
            parts: vec![],
        }
    }
}

pub static AVRO_SCHEMA: &'static str = r#"{
    "type": "record",
    "namespace": "Energistics.Etp.v12.Protocol.GrowingObjectNotification",
    "name": "PartsChanged",
    "protocol": "7",
    "messageType": "2",
    "senderRole": "store",
    "protocolRoles": "store,customer",
    "multipartFlag": false,
    "fields": [
        {
            "name": "uri",
            "type": "string"
        },
        {
            "name": "requestUuid",
            "type": {
                "type": "fixed",
                "namespace": "Energistics.Etp.v12.Datatypes",
                "name": "Uuid",
                "size": 16,
                "fullName": "Energistics.Etp.v12.Datatypes.Uuid",
                "depends": []
            }
        },
        {
            "name": "changeKind",
            "type": {
                "type": "enum",
                "namespace": "Energistics.Etp.v12.Datatypes.Object",
                "name": "ObjectChangeKind",
                "symbols": [
                    "insert",
                    "update",
                    "authorized",
                    "joined",
                    "unjoined",
                    "joinedSubscription",
                    "unjoinedSubscription"
                ],
                "fullName": "Energistics.Etp.v12.Datatypes.Object.ObjectChangeKind",
                "depends": []
            }
        },
        {
            "name": "changeTime",
            "type": "long"
        },
        {
            "name": "format",
            "type": "string",
            "default": ""
        },
        {
            "name": "parts",
            "type": {
                "type": "array",
                "items": {
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
    "fullName": "Energistics.Etp.v12.Protocol.GrowingObjectNotification.PartsChanged",
    "depends": [
        "Energistics.Etp.v12.Datatypes.Uuid",
        "Energistics.Etp.v12.Datatypes.Object.ObjectChangeKind",
        "Energistics.Etp.v12.Datatypes.Object.ObjectPart"
    ]
}"#;
