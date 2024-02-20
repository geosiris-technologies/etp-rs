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

use crate::energistics::etp::v12::datatypes::uuid::{random_uuid, Uuid};
use crate::helpers::ETPMetadata;
use crate::helpers::Schemable;
use crate::protocols::ProtocolMessage;
use apache_avro::{from_avro_datum, from_value, AvroResult};
use std::io::Read;

#[derive(Debug, PartialEq, Clone, serde::Deserialize, serde::Serialize, Derivative)]
#[serde(rename_all = "PascalCase")]
pub struct PartsDeleted {
    #[serde(rename = "uri")]
    pub uri: String,

    #[serde(with = "serde_bytes")]
    #[serde(rename = "requestUuid")]
    pub request_uuid: Uuid,

    #[serde(rename = "changeTime")]
    pub change_time: i64,

    #[serde(rename = "uids")]
    pub uids: Vec<String>,
}

fn partsdeleted_avro_schema() -> Option<Schema> {
    match Schema::parse_str(AVRO_SCHEMA) {
        Ok(result) => Some(result),
        Err(e) => {
            panic!("{:?}", e);
        }
    }
}

impl Schemable for PartsDeleted {
    fn avro_schema(&self) -> Option<Schema> {
        partsdeleted_avro_schema()
    }
    fn avro_schema_str(&self) -> &'static str {
        AVRO_SCHEMA
    }
}

impl AvroSerializable for PartsDeleted {}

impl AvroDeserializable for PartsDeleted {
    fn avro_deserialize<R: Read>(input: &mut R) -> AvroResult<PartsDeleted> {
        let record = from_avro_datum(&partsdeleted_avro_schema().unwrap(), input, None).unwrap();
        from_value::<PartsDeleted>(&record)
    }
}

impl ETPMetadata for PartsDeleted {
    fn protocol(&self) -> i32 {
        7
    }
    fn message_type(&self) -> i32 {
        3
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

impl PartsDeleted {
    pub fn as_protocol_message(&self) -> ProtocolMessage {
        ProtocolMessage::GrowingObjectNotification_PartsDeleted(self.clone())
    }
}

impl PartsDeleted {
    /* Protocol 7, MessageType : 3 */
    pub fn default_with_params(uri: String) -> PartsDeleted {
        PartsDeleted {
            uri,
            request_uuid: random_uuid(),
            change_time: time_to_etp(SystemTime::now()),
            uids: vec![],
        }
    }
}

pub static AVRO_SCHEMA: &'static str = r#"{
    "type": "record",
    "namespace": "Energistics.Etp.v12.Protocol.GrowingObjectNotification",
    "name": "PartsDeleted",
    "protocol": "7",
    "messageType": "3",
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
            "name": "changeTime",
            "type": "long"
        },
        {
            "name": "uids",
            "type": {
                "type": "array",
                "items": "string"
            }
        }
    ],
    "fullName": "Energistics.Etp.v12.Protocol.GrowingObjectNotification.PartsDeleted",
    "depends": [
        "Energistics.Etp.v12.Datatypes.Uuid"
    ]
}"#;
