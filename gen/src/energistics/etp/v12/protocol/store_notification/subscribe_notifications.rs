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
pub struct SubscribeNotifications {
    #[serde(rename = "request")]
    pub request: HashMap<String, SubscriptionInfo>,
}

fn subscribenotifications_avro_schema() -> Option<Schema> {
    match Schema::parse_str(AVRO_SCHEMA) {
        Ok(result) => Some(result),
        Err(e) => {
            panic!("{:?}", e);
        }
    }
}

impl Schemable for SubscribeNotifications {
    fn avro_schema(&self) -> Option<Schema> {
        subscribenotifications_avro_schema()
    }
    fn avro_schema_str(&self) -> &'static str {
        AVRO_SCHEMA
    }
}

impl AvroSerializable for SubscribeNotifications {}

impl AvroDeserializable for SubscribeNotifications {
    fn avro_deserialize<R: Read>(input: &mut R) -> AvroResult<SubscribeNotifications> {
        let record =
            from_avro_datum(&subscribenotifications_avro_schema().unwrap(), input, None).unwrap();
        from_value::<SubscribeNotifications>(&record)
    }
}

impl ETPMetadata for SubscribeNotifications {
    fn protocol(&self) -> i32 {
        5
    }
    fn message_type(&self) -> i32 {
        6
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

impl SubscribeNotifications {
    pub fn as_protocol_message(&self) -> ProtocolMessage {
        ProtocolMessage::StoreNotification_SubscribeNotifications(self.clone())
    }
}

impl Default for SubscribeNotifications {
    /* Protocol 5, MessageType : 6 */
    fn default() -> SubscribeNotifications {
        SubscribeNotifications {
            request: HashMap::new(),
        }
    }
}

pub static AVRO_SCHEMA: &'static str = r#"{
    "type": "record",
    "namespace": "Energistics.Etp.v12.Protocol.StoreNotification",
    "name": "SubscribeNotifications",
    "protocol": "5",
    "messageType": "6",
    "senderRole": "customer",
    "protocolRoles": "store,customer",
    "multipartFlag": false,
    "fields": [
        {
            "name": "request",
            "type": {
                "type": "map",
                "values": {
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
    "fullName": "Energistics.Etp.v12.Protocol.StoreNotification.SubscribeNotifications",
    "depends": [
        "Energistics.Etp.v12.Datatypes.Object.SubscriptionInfo"
    ]
}"#;
