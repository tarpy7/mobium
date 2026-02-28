//! WebSocket protocol tests
//!
//! Tests the MessagePack protocol and message routing logic.

use serde::{Deserialize, Serialize};

// Test message serialization
#[derive(Debug, Serialize, Deserialize, PartialEq)]
struct TestMessage {
    #[serde(rename = "type")]
    msg_type: String,
    payload: Vec<u8>,
    timestamp: i64,
}

#[test]
fn test_messagepack_serialization() {
    let msg = TestMessage {
        msg_type: "test".to_string(),
        payload: vec![0x01, 0x02, 0x03, 0x04],
        timestamp: 1704067200,
    };
    
    // Serialize
    let encoded = rmp_serde::to_vec(&msg).expect("Failed to serialize");
    
    // Deserialize
    let decoded: TestMessage = rmp_serde::from_slice(&encoded).expect("Failed to deserialize");
    
    assert_eq!(msg, decoded);
}

#[test]
fn test_messagepack_binary_data() {
    // Test with encrypted payload-like data
    let payload = vec![0xFF; 1024];
    let msg = TestMessage {
        msg_type: "channel_message".to_string(),
        payload,
        timestamp: 1704067200,
    };
    
    let encoded = rmp_serde::to_vec(&msg).expect("Failed to serialize");
    let decoded: TestMessage = rmp_serde::from_slice(&encoded).expect("Failed to deserialize");
    
    assert_eq!(msg.payload.len(), decoded.payload.len());
    assert_eq!(msg.payload, decoded.payload);
}

#[test]
fn test_messagepack_empty_payload() {
    let msg = TestMessage {
        msg_type: "ping".to_string(),
        payload: vec![],
        timestamp: 0,
    };
    
    let encoded = rmp_serde::to_vec(&msg).expect("Failed to serialize");
    let decoded: TestMessage = rmp_serde::from_slice(&encoded).expect("Failed to deserialize");
    
    assert_eq!(msg, decoded);
}

// Protocol message types
#[derive(Debug, Serialize, Deserialize)]
struct AuthMessage {
    #[serde(rename = "type")]
    msg_type: String,
    pubkey: Vec<u8>,
    signature: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
struct ChannelMessage {
    #[serde(rename = "type")]
    msg_type: String,
    channel_id: Vec<u8>,
    payload: Vec<u8>,
    bucket_size: i64,
}

#[test]
fn test_auth_message_format() {
    let auth = AuthMessage {
        msg_type: "auth".to_string(),
        pubkey: vec![0x01; 32],
        signature: vec![0x02; 64],
    };
    
    let encoded = rmp_serde::to_vec_named(&auth).expect("Failed to serialize");
    
    // Verify it's binary data
    assert!(!encoded.is_empty());
    
    // Deserialize and verify
    let decoded: serde_json::Value = rmp_serde::from_slice(&encoded).expect("Failed to deserialize");
    assert_eq!(decoded["type"], "auth");
}

#[test]
fn test_channel_message_format() {
    let channel_msg = ChannelMessage {
        msg_type: "channel_message".to_string(),
        channel_id: vec![0xAB; 32],
        payload: vec![0xEE; 1024], // Encrypted payload
        bucket_size: 3, // 4KB bucket
    };
    
    let encoded = rmp_serde::to_vec_named(&channel_msg).expect("Failed to serialize");
    
    // Deserialize as JSON for verification
    let decoded: serde_json::Value = rmp_serde::from_slice(&encoded).expect("Failed to deserialize");
    
    assert_eq!(decoded["type"], "channel_message");
    assert!(decoded["bucket_size"].as_i64().is_some());
}

#[test]
fn test_message_size_consistency() {
    // Test that same message serializes to same size
    let msg = TestMessage {
        msg_type: "test".to_string(),
        payload: vec![0x01; 100],
        timestamp: 1234567890,
    };
    
    let encoded1 = rmp_serde::to_vec(&msg).expect("Failed to serialize");
    let encoded2 = rmp_serde::to_vec(&msg).expect("Failed to serialize");
    
    assert_eq!(encoded1.len(), encoded2.len());
}

#[test]
fn test_protocol_version_field() {
    // Verify protocol can handle version info
    #[derive(Debug, Serialize, Deserialize)]
    struct VersionedMessage {
        #[serde(rename = "type")]
        msg_type: String,
        protocol_version: u8,
        payload: Vec<u8>,
    }
    
    let msg = VersionedMessage {
        msg_type: "message".to_string(),
        protocol_version: 1,
        payload: vec![0x01; 50],
    };
    
    let encoded = rmp_serde::to_vec_named(&msg).expect("Failed to serialize");
    let decoded: VersionedMessage = rmp_serde::from_slice(&encoded).expect("Failed to deserialize");
    
    assert_eq!(msg.protocol_version, decoded.protocol_version);
}

// ============================================================================
// Protocol Edge Cases
// ============================================================================

#[test]
fn test_very_large_payload() {
    // Test with 1MB payload (max bucket size)
    let large_payload = vec![0xAA; 1_048_576];
    let msg = TestMessage {
        msg_type: "channel_message".to_string(),
        payload: large_payload,
        timestamp: 0,
    };
    
    let encoded = rmp_serde::to_vec(&msg).expect("Failed to serialize large payload");
    let decoded: TestMessage = rmp_serde::from_slice(&encoded).expect("Failed to deserialize");
    
    assert_eq!(msg.payload.len(), decoded.payload.len());
}

#[test]
fn test_unicode_message_type() {
    // Test with unicode strings
    let msg = TestMessage {
        msg_type: "消息".to_string(), // "message" in Chinese
        payload: vec![0x01; 10],
        timestamp: 0,
    };
    
    let encoded = rmp_serde::to_vec(&msg).expect("Failed to serialize");
    let decoded: TestMessage = rmp_serde::from_slice(&encoded).expect("Failed to deserialize");
    
    assert_eq!(msg.msg_type, decoded.msg_type);
}

#[test]
fn test_corrupted_data_handling() {
    // Test that corrupted data is properly rejected
    let corrupted = vec![0xFF; 10]; // Invalid MessagePack
    
    let result: Result<TestMessage, _> = rmp_serde::from_slice(&corrupted);
    assert!(result.is_err());
}

#[test]
fn test_partial_data_handling() {
    // Test with incomplete data
    let msg = TestMessage {
        msg_type: "test".to_string(),
        payload: vec![0x01; 100],
        timestamp: 0,
    };
    
    let encoded = rmp_serde::to_vec(&msg).expect("Failed to serialize");
    let partial = &encoded[..encoded.len() / 2];
    
    let result: Result<TestMessage, _> = rmp_serde::from_slice(partial);
    assert!(result.is_err());
}

// ============================================================================
// Performance Tests
// ============================================================================

#[test]
fn test_serialization_performance() {
    use std::time::Instant;
    
    let msg = TestMessage {
        msg_type: "channel_message".to_string(),
        payload: vec![0x01; 1024],
        timestamp: 1704067200,
    };
    
    let iterations = 10000;
    
    // Warmup
    for _ in 0..100 {
        let _ = rmp_serde::to_vec(&msg).unwrap();
    }
    
    // Benchmark serialization
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = rmp_serde::to_vec(&msg).unwrap();
    }
    let serialize_time = start.elapsed();
    
    // Benchmark deserialization
    let encoded = rmp_serde::to_vec(&msg).unwrap();
    let start = Instant::now();
    for _ in 0..iterations {
        let _: TestMessage = rmp_serde::from_slice(&encoded).unwrap();
    }
    let deserialize_time = start.elapsed();
    
    let serialize_avg = serialize_time.as_micros() as f64 / iterations as f64;
    let deserialize_avg = deserialize_time.as_micros() as f64 / iterations as f64;
    
    println!("MessagePack performance:");
    println!("  Serialize:   {:.2} μs/iter", serialize_avg);
    println!("  Deserialize: {:.2} μs/iter", deserialize_avg);
    
    // Should be fast (< 50μs on ARM, < 10μs on x86)
    assert!(serialize_avg < 50.0, "serialize too slow: {:.2} μs", serialize_avg);
    assert!(deserialize_avg < 50.0, "deserialize too slow: {:.2} μs", deserialize_avg);
}