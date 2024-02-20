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
pub struct SubscriptionsStopped {
    #[serde(rename = "reason")]
    pub reason: String,

    #[serde(rename = "channelIds")]
    #[derivative(Default(value = "HashMap::new()"))]
    pub channel_ids: HashMap<String, i64>,
}

fn subscriptionsstopped_avro_schema() -> Option<Schema> {
    match Schema::parse_str(AVRO_SCHEMA) {
        Ok(result) => Some(result),
        Err(e) => {
            panic!("{:?}", e);
        }
    }
}

impl Schemable for SubscriptionsStopped {
    fn avro_schema(&self) -> Option<Schema> {
        subscriptionsstopped_avro_schema()
    }
    fn avro_schema_str(&self) -> &'static str {
        AVRO_SCHEMA
    }
}

impl AvroSerializable for SubscriptionsStopped {}

impl AvroDeserializable for SubscriptionsStopped {
    fn avro_deserialize<R: Read>(input: &mut R) -> AvroResult<SubscriptionsStopped> {
        let record =
            from_avro_datum(&subscriptionsstopped_avro_schema().unwrap(), input, None).unwrap();
        from_value::<SubscriptionsStopped>(&record)
    }
}

impl ETPMetadata for SubscriptionsStopped {
    fn protocol(&self) -> i32 {
        21
    }
    fn message_type(&self) -> i32 {
        8
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

impl SubscriptionsStopped {
    pub fn as_protocol_message(&self) -> ProtocolMessage {
        ProtocolMessage::ChannelSubscribe_SubscriptionsStopped(self.clone())
    }
}

impl Default for SubscriptionsStopped {
    /* Protocol 21, MessageType : 8 */
    fn default() -> SubscriptionsStopped {
        SubscriptionsStopped {
            reason: "".to_string(),
            channel_ids: HashMap::new(),
        }
    }
}

pub static AVRO_SCHEMA: &'static str = r#"{
    "type": "record",
    "namespace": "Energistics.Etp.v12.Protocol.ChannelSubscribe",
    "name": "SubscriptionsStopped",
    "protocol": "21",
    "messageType": "8",
    "senderRole": "store",
    "protocolRoles": "store,customer",
    "multipartFlag": true,
    "fields": [
        {
            "name": "reason",
            "type": "string"
        },
        {
            "name": "channelIds",
            "type": {
                "type": "map",
                "values": "long"
            },
            "default": {}
        }
    ],
    "fullName": "Energistics.Etp.v12.Protocol.ChannelSubscribe.SubscriptionsStopped",
    "depends": []
}"#;
