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
pub struct CancelGetRanges {
    #[serde(with = "serde_bytes")]
    #[serde(rename = "requestUuid")]
    pub request_uuid: Uuid,
}

fn cancelgetranges_avro_schema() -> Option<Schema> {
    match Schema::parse_str(AVRO_SCHEMA) {
        Ok(result) => Some(result),
        Err(e) => {
            panic!("{:?}", e);
        }
    }
}

impl Schemable for CancelGetRanges {
    fn avro_schema(&self) -> Option<Schema> {
        cancelgetranges_avro_schema()
    }
    fn avro_schema_str(&self) -> &'static str {
        AVRO_SCHEMA
    }
}

impl AvroSerializable for CancelGetRanges {}

impl AvroDeserializable for CancelGetRanges {
    fn avro_deserialize<R: Read>(input: &mut R) -> AvroResult<CancelGetRanges> {
        let record = from_avro_datum(&cancelgetranges_avro_schema().unwrap(), input, None).unwrap();
        from_value::<CancelGetRanges>(&record)
    }
}

impl ETPMetadata for CancelGetRanges {
    fn protocol(&self) -> i32 {
        21
    }
    fn message_type(&self) -> i32 {
        11
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

impl CancelGetRanges {
    pub fn as_protocol_message(&self) -> ProtocolMessage {
        ProtocolMessage::ChannelSubscribe_CancelGetRanges(self.clone())
    }
}

impl Default for CancelGetRanges {
    /* Protocol 21, MessageType : 11 */
    fn default() -> CancelGetRanges {
        CancelGetRanges {
            request_uuid: random_uuid(),
        }
    }
}

pub static AVRO_SCHEMA: &'static str = r#"{
    "type": "record",
    "namespace": "Energistics.Etp.v12.Protocol.ChannelSubscribe",
    "name": "CancelGetRanges",
    "protocol": "21",
    "messageType": "11",
    "senderRole": "customer",
    "protocolRoles": "store,customer",
    "multipartFlag": false,
    "fields": [
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
        }
    ],
    "fullName": "Energistics.Etp.v12.Protocol.ChannelSubscribe.CancelGetRanges",
    "depends": [
        "Energistics.Etp.v12.Datatypes.Uuid"
    ]
}"#;
