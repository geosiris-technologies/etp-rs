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
pub struct CommitTransaction {
    #[serde(with = "serde_bytes")]
    #[serde(rename = "transactionUuid")]
    pub transaction_uuid: Uuid,
}

fn committransaction_avro_schema() -> Option<Schema> {
    match Schema::parse_str(AVRO_SCHEMA) {
        Ok(result) => Some(result),
        Err(e) => {
            panic!("{:?}", e);
        }
    }
}

impl Schemable for CommitTransaction {
    fn avro_schema(&self) -> Option<Schema> {
        committransaction_avro_schema()
    }
    fn avro_schema_str(&self) -> &'static str {
        AVRO_SCHEMA
    }
}

impl AvroSerializable for CommitTransaction {}

impl AvroDeserializable for CommitTransaction {
    fn avro_deserialize<R: Read>(input: &mut R) -> AvroResult<CommitTransaction> {
        let record =
            from_avro_datum(&committransaction_avro_schema().unwrap(), input, None).unwrap();
        from_value::<CommitTransaction>(&record)
    }
}

impl ETPMetadata for CommitTransaction {
    fn protocol(&self) -> i32 {
        18
    }
    fn message_type(&self) -> i32 {
        3
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

impl CommitTransaction {
    pub fn as_protocol_message(&self) -> ProtocolMessage {
        ProtocolMessage::Transaction_CommitTransaction(self.clone())
    }
}

impl Default for CommitTransaction {
    /* Protocol 18, MessageType : 3 */
    fn default() -> CommitTransaction {
        CommitTransaction {
            transaction_uuid: random_uuid(),
        }
    }
}

pub static AVRO_SCHEMA: &'static str = r#"{
    "type": "record",
    "namespace": "Energistics.Etp.v12.Protocol.Transaction",
    "name": "CommitTransaction",
    "protocol": "18",
    "messageType": "3",
    "senderRole": "customer",
    "protocolRoles": "store,customer",
    "multipartFlag": false,
    "fields": [
        {
            "name": "transactionUuid",
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
    "fullName": "Energistics.Etp.v12.Protocol.Transaction.CommitTransaction",
    "depends": [
        "Energistics.Etp.v12.Datatypes.Uuid"
    ]
}"#;
