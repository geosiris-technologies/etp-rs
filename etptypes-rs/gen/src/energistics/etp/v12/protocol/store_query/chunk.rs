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
pub struct Chunk {
    #[serde(with = "serde_bytes")]
    #[serde(rename = "blobId")]
    pub blob_id: Uuid,

    #[serde(with = "serde_bytes")]
    #[serde(rename = "data")]
    pub data: Vec<u8>,

    #[serde(rename = "final")]
    pub final_: bool,
}

fn chunk_avro_schema() -> Option<Schema> {
    match Schema::parse_str(AVRO_SCHEMA) {
        Ok(result) => Some(result),
        Err(e) => {
            panic!("{:?}", e);
        }
    }
}

impl Schemable for Chunk {
    fn avro_schema(&self) -> Option<Schema> {
        chunk_avro_schema()
    }
    fn avro_schema_str(&self) -> &'static str {
        AVRO_SCHEMA
    }
}

impl AvroSerializable for Chunk {}

impl AvroDeserializable for Chunk {
    fn avro_deserialize<R: Read>(input: &mut R) -> AvroResult<Chunk> {
        let record = from_avro_datum(&chunk_avro_schema().unwrap(), input, None).unwrap();
        from_value::<Chunk>(&record)
    }
}

impl ETPMetadata for Chunk {
    fn protocol(&self) -> i32 {
        14
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
        true
    }
}

impl Chunk {
    pub fn as_protocol_message(&self) -> ProtocolMessage {
        ProtocolMessage::StoreQuery_Chunk(self.clone())
    }
}

impl Chunk {
    /* Protocol 14, MessageType : 3 */
    pub fn default_with_params(data: Vec<u8>) -> Chunk {
        Chunk {
            blob_id: random_uuid(),
            data,
            final_: true,
        }
    }
}

pub static AVRO_SCHEMA: &'static str = r#"{
    "type": "record",
    "namespace": "Energistics.Etp.v12.Protocol.StoreQuery",
    "name": "Chunk",
    "protocol": "14",
    "messageType": "3",
    "senderRole": "store",
    "protocolRoles": "store,customer",
    "multipartFlag": true,
    "fields": [
        {
            "name": "blobId",
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
            "name": "data",
            "type": "bytes"
        },
        {
            "name": "final",
            "type": "boolean"
        }
    ],
    "fullName": "Energistics.Etp.v12.Protocol.StoreQuery.Chunk",
    "depends": [
        "Energistics.Etp.v12.Datatypes.Uuid"
    ]
}"#;
