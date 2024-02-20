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

use crate::energistics::etp::v12::datatypes::object::subscription_info::SubscriptionInfo;
use crate::helpers::ETPMetadata;
use crate::helpers::Schemable;
use crate::protocols::ProtocolMessage;
use apache_avro::{from_avro_datum, from_value, AvroResult};
use std::io::Read;

#[derive(Debug, PartialEq, Clone, serde::Deserialize, serde::Serialize, Derivative)]
#[serde(rename_all = "PascalCase")]
pub struct UnsolicitedStoreNotifications {
    #[serde(rename = "subscriptions")]
    pub subscriptions: Vec<SubscriptionInfo>,
}

fn unsolicitedstorenotifications_avro_schema() -> Option<Schema> {
    match Schema::parse_str(AVRO_SCHEMA) {
        Ok(result) => Some(result),
        Err(e) => {
            panic!("{:?}", e);
        }
    }
}

impl Schemable for UnsolicitedStoreNotifications {
    fn avro_schema(&self) -> Option<Schema> {
        unsolicitedstorenotifications_avro_schema()
    }
    fn avro_schema_str(&self) -> &'static str {
        AVRO_SCHEMA
    }
}

impl AvroSerializable for UnsolicitedStoreNotifications {}

impl AvroDeserializable for UnsolicitedStoreNotifications {
    fn avro_deserialize<R: Read>(input: &mut R) -> AvroResult<UnsolicitedStoreNotifications> {
        let record = from_avro_datum(
            &unsolicitedstorenotifications_avro_schema().unwrap(),
            input,
            None,
        )
        .unwrap();
        from_value::<UnsolicitedStoreNotifications>(&record)
    }
}

impl ETPMetadata for UnsolicitedStoreNotifications {
    fn protocol(&self) -> i32 {
        5
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
        false
    }
}

impl UnsolicitedStoreNotifications {
    pub fn as_protocol_message(&self) -> ProtocolMessage {
        ProtocolMessage::StoreNotification_UnsolicitedStoreNotifications(self.clone())
    }
}

impl Default for UnsolicitedStoreNotifications {
    /* Protocol 5, MessageType : 8 */
    fn default() -> UnsolicitedStoreNotifications {
        UnsolicitedStoreNotifications {
            subscriptions: vec![],
        }
    }
}

pub static AVRO_SCHEMA: &'static str = r#"{
    "type": "record",
    "namespace": "Energistics.Etp.v12.Protocol.StoreNotification",
    "name": "UnsolicitedStoreNotifications",
    "protocol": "5",
    "messageType": "8",
    "senderRole": "store",
    "protocolRoles": "store,customer",
    "multipartFlag": false,
    "fields": [
        {
            "name": "subscriptions",
            "type": {
                "type": "array",
                "items": {
                    "type": "record",
                    "namespace": "Energistics.Etp.v12.Datatypes.Object",
                    "name": "SubscriptionInfo",
                    "fields": [
                        {
                            "name": "context",
                            "type": {
                                "type": "record",
                                "namespace": "Energistics.Etp.v12.Datatypes.Object",
                                "name": "ContextInfo",
                                "fields": [
                                    {
                                        "name": "uri",
                                        "type": "string"
                                    },
                                    {
                                        "name": "depth",
                                        "type": "int"
                                    },
                                    {
                                        "name": "dataObjectTypes",
                                        "type": {
                                            "type": "array",
                                            "items": "string"
                                        },
                                        "default": []
                                    },
                                    {
                                        "name": "navigableEdges",
                                        "type": {
                                            "type": "enum",
                                            "namespace": "Energistics.Etp.v12.Datatypes.Object",
                                            "name": "RelationshipKind",
                                            "symbols": [
                                                "Primary",
                                                "Secondary",
                                                "Both"
                                            ],
                                            "fullName": "Energistics.Etp.v12.Datatypes.Object.RelationshipKind",
                                            "depends": []
                                        }
                                    },
                                    {
                                        "name": "includeSecondaryTargets",
                                        "type": "boolean",
                                        "default": false
                                    },
                                    {
                                        "name": "includeSecondarySources",
                                        "type": "boolean",
                                        "default": false
                                    }
                                ],
                                "fullName": "Energistics.Etp.v12.Datatypes.Object.ContextInfo",
                                "depends": [
                                    "Energistics.Etp.v12.Datatypes.Object.RelationshipKind"
                                ]
                            }
                        },
                        {
                            "name": "scope",
                            "type": {
                                "type": "enum",
                                "namespace": "Energistics.Etp.v12.Datatypes.Object",
                                "name": "ContextScopeKind",
                                "symbols": [
                                    "self",
                                    "sources",
                                    "targets",
                                    "sourcesOrSelf",
                                    "targetsOrSelf"
                                ],
                                "fullName": "Energistics.Etp.v12.Datatypes.Object.ContextScopeKind",
                                "depends": []
                            }
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
                            "name": "includeObjectData",
                            "type": "boolean"
                        },
                        {
                            "name": "format",
                            "type": "string",
                            "default": "xml"
                        }
                    ],
                    "fullName": "Energistics.Etp.v12.Datatypes.Object.SubscriptionInfo",
                    "depends": [
                        "Energistics.Etp.v12.Datatypes.Object.ContextInfo",
                        "Energistics.Etp.v12.Datatypes.Object.ContextScopeKind",
                        "Energistics.Etp.v12.Datatypes.Uuid"
                    ]
                }
            }
        }
    ],
    "fullName": "Energistics.Etp.v12.Protocol.StoreNotification.UnsolicitedStoreNotifications",
    "depends": [
        "Energistics.Etp.v12.Datatypes.Object.SubscriptionInfo"
    ]
}"#;
