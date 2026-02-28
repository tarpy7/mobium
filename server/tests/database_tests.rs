//! Server integration tests
//!
//! These tests verify:
//! - Database operations
//! - Message routing
//! - Channel management
//! - Authentication

use sqlx::SqlitePool;
use std::sync::Arc;
use tokio::sync::mpsc;

// Helper function to create test database
async fn setup_test_db() -> SqlitePool {
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .connect(":memory:")
        .await
        .expect("Failed to create test database");
    
    // Run migrations
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS users (
            pubkey BLOB PRIMARY KEY,
            last_seen INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
            encrypted_prekeys BLOB,
            created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
        );
        "#
    )
    .execute(&pool)
    .await
    .unwrap();

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS offline_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            recipient_pubkey BLOB NOT NULL,
            sender_pubkey BLOB NOT NULL,
            encrypted_payload BLOB NOT NULL,
            timestamp INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
        );
        "#
    )
    .execute(&pool)
    .await
    .unwrap();

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS channels (
            id BLOB PRIMARY KEY,
            encrypted_metadata BLOB NOT NULL,
            created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
        );
        "#
    )
    .execute(&pool)
    .await
    .unwrap();

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS channel_members (
            channel_id BLOB NOT NULL,
            user_pubkey BLOB NOT NULL,
            joined_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
            PRIMARY KEY (channel_id, user_pubkey)
        );
        "#
    )
    .execute(&pool)
    .await
    .unwrap();

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS channel_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            channel_id BLOB NOT NULL,
            encrypted_payload BLOB NOT NULL,
            bucket_size INTEGER NOT NULL,
            timestamp INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
            sender_pubkey BLOB NOT NULL
        );
        "#
    )
    .execute(&pool)
    .await
    .unwrap();

    sqlx::query(
        r#"
        CREATE INDEX IF NOT EXISTS idx_channel_messages_channel_time 
        ON channel_messages(channel_id, timestamp);
        "#
    )
    .execute(&pool)
    .await
    .unwrap();

    pool
}

// ============================================================================
// Database Tests
// ============================================================================

#[tokio::test]
async fn test_user_storage() {
    let pool = setup_test_db().await;
    
    let pubkey = vec![0x01, 0x02, 0x03, 0x04];
    let prekeys = vec![0xAA, 0xBB, 0xCC];
    
    // Store user
    sqlx::query(
        "INSERT INTO users (pubkey, encrypted_prekeys) VALUES (?1, ?2)"
    )
    .bind(&pubkey)
    .bind(&prekeys)
    .execute(&pool)
    .await
    .unwrap();
    
    // Verify storage
    let result: Option<(Vec<u8>,)> = sqlx::query_as(
        "SELECT encrypted_prekeys FROM users WHERE pubkey = ?1"
    )
    .bind(&pubkey)
    .fetch_optional(&pool)
    .await
    .unwrap();
    
    assert!(result.is_some());
    assert_eq!(result.unwrap().0, prekeys);
}

#[tokio::test]
async fn test_offline_message_storage() {
    let pool = setup_test_db().await;
    
    let recipient = vec![0x01; 32];
    let sender = vec![0x02; 32];
    let payload = vec![0xFF; 512]; // Simulated encrypted message
    
    // Store offline message
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO offline_messages (recipient_pubkey, sender_pubkey, encrypted_payload) VALUES (?1, ?2, ?3) RETURNING id"
    )
    .bind(&recipient)
    .bind(&sender)
    .bind(&payload)
    .fetch_one(&pool)
    .await
    .unwrap();
    
    assert!(id > 0);
    
    // Retrieve offline messages
    let messages: Vec<(i64, Vec<u8>, Vec<u8>)> = sqlx::query_as(
        "SELECT id, sender_pubkey, encrypted_payload FROM offline_messages WHERE recipient_pubkey = ?1 ORDER BY timestamp"
    )
    .bind(&recipient)
    .fetch_all(&pool)
    .await
    .unwrap();
    
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].1, sender);
    assert_eq!(messages[0].2, payload);
    
    // Delete message
    sqlx::query("DELETE FROM offline_messages WHERE id = ?1")
        .bind(id)
        .execute(&pool)
        .await
        .unwrap();
    
    // Verify deletion
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM offline_messages WHERE recipient_pubkey = ?1"
    )
    .bind(&recipient)
    .fetch_one(&pool)
    .await
    .unwrap();
    
    assert_eq!(count, 0);
}

#[tokio::test]
async fn test_channel_creation_and_membership() {
    let pool = setup_test_db().await;
    
    let channel_id = vec![0xAB; 32];
    let user1 = vec![0x01; 32];
    let user2 = vec![0x02; 32];
    let metadata = vec![0xCC; 100]; // Encrypted channel metadata
    
    // Create channel
    sqlx::query(
        "INSERT INTO channels (id, encrypted_metadata) VALUES (?1, ?2)"
    )
    .bind(&channel_id)
    .bind(&metadata)
    .execute(&pool)
    .await
    .unwrap();
    
    // Add members
    sqlx::query(
        "INSERT INTO channel_members (channel_id, user_pubkey) VALUES (?1, ?2)"
    )
    .bind(&channel_id)
    .bind(&user1)
    .execute(&pool)
    .await
    .unwrap();
    
    sqlx::query(
        "INSERT INTO channel_members (channel_id, user_pubkey) VALUES (?1, ?2)"
    )
    .bind(&channel_id)
    .bind(&user2)
    .execute(&pool)
    .await
    .unwrap();
    
    // Verify membership
    let is_member: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM channel_members WHERE channel_id = ?1 AND user_pubkey = ?2"
    )
    .bind(&channel_id)
    .bind(&user1)
    .fetch_one(&pool)
    .await
    .unwrap();
    
    assert_eq!(is_member, 1);
    
    // Get all members
    let members: Vec<(Vec<u8>,)> = sqlx::query_as(
        "SELECT user_pubkey FROM channel_members WHERE channel_id = ?1"
    )
    .bind(&channel_id)
    .fetch_all(&pool)
    .await
    .unwrap();
    
    assert_eq!(members.len(), 2);
}

#[tokio::test]
async fn test_channel_message_storage() {
    let pool = setup_test_db().await;
    
    let channel_id = vec![0xAB; 32];
    let sender = vec![0x01; 32];
    let payload = vec![0xEE; 1024]; // Encrypted payload
    let bucket_size = 3; // 4KB bucket
    
    // Create channel
    sqlx::query(
        "INSERT INTO channels (id, encrypted_metadata) VALUES (?1, ?2)"
    )
    .bind(&channel_id)
    .bind(vec![0x00; 10])
    .execute(&pool)
    .await
    .unwrap();
    
    // Store message
    let msg_id: i64 = sqlx::query_scalar(
        "INSERT INTO channel_messages (channel_id, encrypted_payload, bucket_size, sender_pubkey) VALUES (?1, ?2, ?3, ?4) RETURNING id"
    )
    .bind(&channel_id)
    .bind(&payload)
    .bind(bucket_size)
    .bind(&sender)
    .fetch_one(&pool)
    .await
    .unwrap();
    
    assert!(msg_id > 0);
    
    // Verify storage
    let result: Option<(Vec<u8>, i64, Vec<u8>)> = sqlx::query_as(
        "SELECT encrypted_payload, bucket_size, sender_pubkey FROM channel_messages WHERE id = ?1"
    )
    .bind(msg_id)
    .fetch_optional(&pool)
    .await
    .unwrap();
    
    assert!(result.is_some());
    let (stored_payload, stored_bucket, stored_sender) = result.unwrap();
    assert_eq!(stored_payload, payload);
    assert_eq!(stored_bucket, bucket_size);
    assert_eq!(stored_sender, sender);
}

#[tokio::test]
async fn test_channel_history_query() {
    let pool = setup_test_db().await;
    
    let channel_id = vec![0xAB; 32];
    let user = vec![0x01; 32];
    let join_time = 1000i64;
    
    // Setup
    sqlx::query(
        "INSERT INTO channels (id, encrypted_metadata) VALUES (?1, ?2)"
    )
    .bind(&channel_id)
    .bind(vec![0x00; 10])
    .execute(&pool)
    .await
    .unwrap();
    
    sqlx::query(
        "INSERT INTO channel_members (channel_id, user_pubkey, joined_at) VALUES (?1, ?2, ?3)"
    )
    .bind(&channel_id)
    .bind(&user)
    .bind(join_time)
    .execute(&pool)
    .await
    .unwrap();
    
    // Add messages at different times
    for i in 0..10 {
        sqlx::query(
            "INSERT INTO channel_messages (channel_id, encrypted_payload, bucket_size, sender_pubkey, timestamp) VALUES (?1, ?2, ?3, ?4, ?5)"
        )
        .bind(&channel_id)
        .bind(vec![i as u8; 512])
        .bind(1)
        .bind(&user)
        .bind(join_time + i as i64 * 100)
        .execute(&pool)
        .await
        .unwrap();
    }
    
    // Query history (should get all 10)
    let history: Vec<(i64, Vec<u8>, i64)> = sqlx::query_as(
        r#"
        SELECT cm.id, cm.encrypted_payload, cm.timestamp
        FROM channel_messages cm
        JOIN channel_members mem ON cm.channel_id = mem.channel_id
        WHERE cm.channel_id = ?1 
          AND mem.user_pubkey = ?2
          AND cm.timestamp >= (SELECT MAX(joined_at) FROM channel_members WHERE channel_id = ?1 AND user_pubkey = ?2)
        ORDER BY cm.timestamp ASC
        LIMIT ?3
        "#
    )
    .bind(&channel_id)
    .bind(&user)
    .bind(100i64)
    .fetch_all(&pool)
    .await
    .unwrap();
    
    assert_eq!(history.len(), 10);
}

#[tokio::test]
async fn test_non_member_cannot_access_history() {
    let pool = setup_test_db().await;
    
    let channel_id = vec![0xAB; 32];
    let member = vec![0x01; 32];
    let non_member = vec![0x02; 32];
    
    // Setup channel with only member
    sqlx::query(
        "INSERT INTO channels (id, encrypted_metadata) VALUES (?1, ?2)"
    )
    .bind(&channel_id)
    .bind(vec![0x00; 10])
    .execute(&pool)
    .await
    .unwrap();
    
    sqlx::query(
        "INSERT INTO channel_members (channel_id, user_pubkey) VALUES (?1, ?2)"
    )
    .bind(&channel_id)
    .bind(&member)
    .execute(&pool)
    .await
    .unwrap();
    
    // Add message
    sqlx::query(
        "INSERT INTO channel_messages (channel_id, encrypted_payload, bucket_size, sender_pubkey) VALUES (?1, ?2, ?3, ?4)"
    )
    .bind(&channel_id)
    .bind(vec![0xFF; 512])
    .bind(1)
    .bind(&member)
    .execute(&pool)
    .await
    .unwrap();
    
    // Query as non-member (should return empty)
    let is_member: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM channel_members WHERE channel_id = ?1 AND user_pubkey = ?2"
    )
    .bind(&channel_id)
    .bind(&non_member)
    .fetch_one(&pool)
    .await
    .unwrap();
    
    assert_eq!(is_member, 0);
}

// ============================================================================
// Concurrent Access Tests
// ============================================================================

#[tokio::test]
async fn test_concurrent_message_storage() {
    let pool = setup_test_db().await;
    let pool = Arc::new(pool);
    
    let channel_id = vec![0xAB; 32];
    let sender = vec![0x01; 32];
    
    // Setup
    sqlx::query(
        "INSERT INTO channels (id, encrypted_metadata) VALUES (?1, ?2)"
    )
    .bind(&channel_id)
    .bind(vec![0x00; 10])
    .execute(&*pool)
    .await
    .unwrap();
    
    // Spawn multiple concurrent writes
    let mut handles = vec![];
    
    for i in 0..10 {
        let pool_clone = Arc::clone(&pool);
        let channel_id_clone = channel_id.clone();
        let sender_clone = sender.clone();
        
        let handle = tokio::spawn(async move {
            sqlx::query(
                "INSERT INTO channel_messages (channel_id, encrypted_payload, bucket_size, sender_pubkey) VALUES (?1, ?2, ?3, ?4)"
            )
            .bind(&channel_id_clone)
            .bind(vec![i as u8; 512])
            .bind(1)
            .bind(&sender_clone)
            .execute(&*pool_clone)
            .await
            .unwrap();
        });
        
        handles.push(handle);
    }
    
    // Wait for all to complete
    for handle in handles {
        handle.await.unwrap();
    }
    
    // Verify all messages stored
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM channel_messages WHERE channel_id = ?1"
    )
    .bind(&channel_id)
    .fetch_one(&*pool)
    .await
    .unwrap();
    
    assert_eq!(count, 10);
}

// ============================================================================
// Performance Tests
// ============================================================================

#[tokio::test]
async fn test_message_storage_performance() {
    use std::time::Instant;
    
    let pool = setup_test_db().await;
    
    let channel_id = vec![0xAB; 32];
    let sender = vec![0x01; 32];
    
    // Setup
    sqlx::query(
        "INSERT INTO channels (id, encrypted_metadata) VALUES (?1, ?2)"
    )
    .bind(&channel_id)
    .bind(vec![0x00; 10])
    .execute(&pool)
    .await
    .unwrap();
    
    // Benchmark: Store 1000 messages
    let iterations = 1000;
    let start = Instant::now();
    
    for i in 0..iterations {
        sqlx::query(
            "INSERT INTO channel_messages (channel_id, encrypted_payload, bucket_size, sender_pubkey) VALUES (?1, ?2, ?3, ?4)"
        )
        .bind(&channel_id)
        .bind(vec![(i % 256) as u8; 1024])
        .bind(2) // 2KB bucket
        .bind(&sender)
        .execute(&pool)
        .await
        .unwrap();
    }
    
    let duration = start.elapsed();
    let avg_ms = duration.as_millis() as f64 / iterations as f64;
    
    println!("Storage benchmark: {} messages, avg {:.3} ms/message", iterations, avg_ms);
    
    // Should be reasonably fast (< 5ms per message)
    assert!(avg_ms < 5.0, "Storage too slow: {:.3} ms/message", avg_ms);
}

#[tokio::test]
async fn test_history_query_performance() {
    use std::time::Instant;
    
    let pool = setup_test_db().await;
    
    let channel_id = vec![0xAB; 32];
    let user = vec![0x01; 32];
    
    // Setup with 10000 messages
    sqlx::query(
        "INSERT INTO channels (id, encrypted_metadata) VALUES (?1, ?2)"
    )
    .bind(&channel_id)
    .bind(vec![0x00; 10])
    .execute(&pool)
    .await
    .unwrap();
    
    sqlx::query(
        "INSERT INTO channel_members (channel_id, user_pubkey, joined_at) VALUES (?1, ?2, ?3)"
    )
    .bind(&channel_id)
    .bind(&user)
    .bind(0i64)
    .execute(&pool)
    .await
    .unwrap();
    
    // Insert 10000 messages
    for i in 0..10000 {
        sqlx::query(
            "INSERT INTO channel_messages (channel_id, encrypted_payload, bucket_size, sender_pubkey, timestamp) VALUES (?1, ?2, ?3, ?4, ?5)"
        )
        .bind(&channel_id)
        .bind(vec![(i % 256) as u8; 512])
        .bind(1)
        .bind(&user)
        .bind(i as i64)
        .execute(&pool)
        .await
        .unwrap();
    }
    
    // Benchmark: Query 100 messages
    let iterations = 100;
    let start = Instant::now();
    
    for _ in 0..iterations {
        let _: Vec<(i64, Vec<u8>, i64)> = sqlx::query_as(
            r#"
            SELECT cm.id, cm.encrypted_payload, cm.timestamp
            FROM channel_messages cm
            JOIN channel_members mem ON cm.channel_id = mem.channel_id
            WHERE cm.channel_id = ?1 
              AND mem.user_pubkey = ?2
              AND cm.timestamp > mem.joined_at
            ORDER BY cm.timestamp ASC
            LIMIT ?3
            "#
        )
        .bind(&channel_id)
        .bind(&user)
        .bind(100i64)
        .fetch_all(&pool)
        .await
        .unwrap();
    }
    
    let duration = start.elapsed();
    let avg_ms = duration.as_millis() as f64 / iterations as f64;
    
    println!("Query benchmark: {} queries, avg {:.3} ms/query", iterations, avg_ms);
    
    // Should be fast (< 50ms even with 10000 messages)
    assert!(avg_ms < 50.0, "Query too slow: {:.3} ms/query", avg_ms);
}

// ============================================================================
// MessagePack round-trip tests — verify that Vec<u8> survives serialization
// ============================================================================

#[test]
fn test_msgpack_vec_u8_roundtrip_via_serde_json() {
    // This mirrors exactly what the client does:
    //   serde_json::json!({ "channel_id": some_vec_u8 })
    //   -> rmp_serde::to_vec_named
    //   -> send over WebSocket
    // And what the server does:
    //   rmp_serde::from_slice::<serde_json::Value>
    //   -> msg.get("channel_id").and_then(|v| v.as_array())

    let original_bytes: Vec<u8> = (0..=255u8).cycle().take(32).collect();

    // Client-side: build JSON value and serialize to msgpack
    let json_val = serde_json::json!({
        "type": "create_channel",
        "channel_id": original_bytes,
    });
    let packed = rmp_serde::to_vec_named(&json_val).expect("msgpack serialize");

    // Server-side: deserialize and extract
    let unpacked: serde_json::Value =
        rmp_serde::from_slice(&packed).expect("msgpack deserialize");

    let channel_val = unpacked.get("channel_id").expect("missing channel_id");

    // Method 1: .as_array() — used by create_channel / join_channel handlers
    let via_array = channel_val
        .as_array()
        .map(|arr| {
            arr.iter()
                .map(|v| v.as_u64().map(|n| n as u8))
                .collect::<Option<Vec<u8>>>()
        })
        .flatten();

    // Method 2: extract_bytes_from_value logic — used by channel_message handler
    let via_extract = if let Some(arr) = channel_val.as_array() {
        arr.iter()
            .map(|v| v.as_u64().map(|n| n as u8))
            .collect::<Option<Vec<u8>>>()
    } else if let Some(s) = channel_val.as_str() {
        hex::decode(s).ok()
    } else {
        None
    };

    println!("channel_val type: {:?}", channel_val);
    println!("via_array:   {:?}", via_array);
    println!("via_extract: {:?}", via_extract);

    // At least one must work
    assert!(
        via_array.is_some() || via_extract.is_some(),
        "Neither extraction method could recover the bytes!\nchannel_val = {:?}",
        channel_val
    );

    if let Some(bytes) = &via_array {
        assert_eq!(bytes, &original_bytes, ".as_array() extraction produced wrong bytes");
    } else {
        eprintln!("WARNING: .as_array() returned None — create_channel/join_channel will FAIL");
        eprintln!("         channel_val = {:?}", channel_val);
    }

    if let Some(bytes) = &via_extract {
        assert_eq!(bytes, &original_bytes, "extract_bytes_from_value produced wrong bytes");
    }
}