use liteseal_core::trusted_devices::messages::api::{DirectApi, RemoteState};
use liteseal_shared::{
    crypto,
    direct_message::{Ack, Batch, Header, Kind, MessageSpec},
    direct_transport::{Delivery, Page, Receipt, Result as Outcome},
    protocol::AckOutcome,
    trusted_device::*,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};
fn fixture(origin: &str) -> (Batch, Ack, String, String) {
    let a = crypto::generate_keypair().unwrap();
    let b = crypto::generate_keypair().unwrap();
    let state = |keys: &crypto::KeyPair| {
        DeviceState::pin(Anchor {
            origin: origin.into(),
            account: uuid::Uuid::new_v4().to_string(),
            root: DeviceIdentity::from_keys(uuid::Uuid::new_v4().to_string(), keys),
        })
        .unwrap()
    };
    let s = state(&a);
    let p = state(&b);
    let batch = Batch::make(
        Header::new(
            &s,
            &p,
            &s.anchor().root.device_id,
            MessageSpec {
                id: uuid::Uuid::new_v4().to_string(),
                sequence: 1,
                previous: vec![],
                sent_at: 1,
                kind: Kind::Text,
            },
        )
        .unwrap(),
        &s,
        &p,
        &a,
        b"synthetic",
    )
    .unwrap();
    let ack = Ack::make(
        &batch,
        &s,
        &p,
        &p.anchor().account,
        &p.anchor().root.device_id,
        &b,
        AckOutcome::Processed,
    )
    .unwrap();
    (
        batch,
        ack,
        p.anchor().account.clone(),
        p.anchor().root.device_id.clone(),
    )
}
async fn server(listener: TcpListener, response: Vec<u8>) -> Vec<u8> {
    let (mut socket, _) = listener.accept().await.unwrap();
    let mut request = vec![];
    let mut buf = [0; 4096];
    loop {
        let n = socket.read(&mut buf).await.unwrap();
        assert!(n > 0);
        request.extend_from_slice(&buf[..n]);
        if let Some(end) = request.windows(4).position(|v| v == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&request[..end]).to_lowercase();
            let len = head
                .lines()
                .find_map(|line| {
                    line.strip_prefix("content-length: ")
                        .and_then(|v| v.parse::<usize>().ok())
                })
                .unwrap_or(0);
            if request.len() >= end + 4 + len {
                break;
            }
        }
    }
    socket.write_all(&response).await.unwrap();
    request
}
fn response(status: &str, body: &[u8]) -> Vec<u8> {
    let mut out=format!("HTTP/1.1 {status}\r\nContent-Length: {}\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n",body.len()).into_bytes();
    out.extend_from_slice(body);
    out
}
fn receipt(b: &Batch) -> Receipt {
    Receipt {
        id: b.header.id.clone(),
        digest: b.digest().unwrap(),
        accepted_at: 123,
    }
}
async fn listener() -> (TcpListener, String) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", l.local_addr().unwrap());
    (l, url)
}
#[tokio::test]
async fn bound_receipt_and_unknown_query_are_distinct_from_cancel_confirmation() {
    for mode in 0..3 {
        let (l, url) = listener().await;
        let (batch, _, _, _) = fixture(&url);
        let outcome = if mode == 0 {
            Outcome::Accepted {
                receipt: receipt(&batch),
                acknowledgements: vec![],
            }
        } else {
            Outcome::Unknown {
                id: batch.header.id.clone(),
                digest: batch.digest().unwrap(),
            }
        };
        let task = tokio::spawn(server(
            l,
            response("200 OK", &serde_json::to_vec(&outcome).unwrap()),
        ));
        let api = DirectApi::new(&url).unwrap();
        let result = if mode == 2 {
            api.cancel("synthetic-token", &batch).await
        } else {
            api.lookup("synthetic-token", &batch).await
        };
        if mode == 2 {
            assert!(result.is_err());
        } else {
            assert_eq!(
                result.unwrap().state(),
                if mode == 0 {
                    RemoteState::Accepted
                } else {
                    RemoteState::Unknown
                }
            );
        }
        task.await.unwrap();
    }
}
#[tokio::test]
async fn response_identity_digest_time_duplicate_ack_and_unknown_fields_are_rejected() {
    for mode in 0..5 {
        let (l, url) = listener().await;
        let (batch, ack, _, _) = fixture(&url);
        let mut r = receipt(&batch);
        if mode == 0 {
            r.id = uuid::Uuid::new_v4().to_string();
        }
        if mode == 1 {
            r.digest[0] ^= 1;
        }
        if mode == 2 {
            r.accepted_at = 0;
        }
        let result = Outcome::Accepted {
            receipt: r,
            acknowledgements: if mode == 3 {
                vec![ack.clone(), ack]
            } else {
                vec![]
            },
        };
        let mut value = serde_json::to_value(&result).unwrap();
        if mode == 4 {
            value["extra"] = serde_json::json!(true);
        }
        let task = tokio::spawn(server(
            l,
            response("200 OK", &serde_json::to_vec(&value).unwrap()),
        ));
        assert!(DirectApi::new(&url)
            .unwrap()
            .lookup("synthetic-token", &batch)
            .await
            .is_err());
        task.await.unwrap();
    }
}
#[tokio::test]
async fn pending_pages_bind_recipient_order_count_origin_and_receipt() {
    for mode in 0..6 {
        let (l, url) = listener().await;
        let (batch, _, account, device) = fixture(&url);
        let item = Delivery {
            order: 1,
            receipt: receipt(&batch),
            batch,
        };
        let mut page = Page {
            items: vec![item.clone()],
            has_more: false,
        };
        match mode {
            1 => page.items.push(item),
            2 => page.items[0].order = 0,
            3 => {
                page.items.clear();
                page.has_more = true;
            }
            4 => page.items[0].batch.header.origin = "https://foreign.invalid".into(),
            5 => page.items[0].receipt.digest[0] ^= 1,
            _ => {}
        }
        let task = tokio::spawn(server(
            l,
            response("200 OK", &serde_json::to_vec(&page).unwrap()),
        ));
        let result = DirectApi::new(&url)
            .unwrap()
            .pending("synthetic-token", &account, &device, 1)
            .await;
        assert_eq!(result.is_ok(), mode == 0);
        if let Ok(page) = result {
            assert_eq!(page.len(), 1);
        }
        task.await.unwrap();
    }
}
#[tokio::test]
async fn redirects_do_not_forward_credentials_and_ack_requires_exact_success_status() {
    let (l, url) = listener().await;
    let (batch, _, _, _) = fixture(&url);
    let second = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let destination = format!("http://{}/other", second.local_addr().unwrap());
    let task=tokio::spawn(server(l,format!("HTTP/1.1 307 Temporary Redirect\r\nLocation: {destination}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").into_bytes()));
    assert_eq!(
        DirectApi::new(&url)
            .unwrap()
            .lookup("synthetic-token", &batch)
            .await
            .err()
            .unwrap()
            .status,
        Some(307)
    );
    task.await.unwrap();
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(30), second.accept())
            .await
            .is_err()
    );
    for (status, ok) in [
        ("204 No Content", true),
        ("200 OK", false),
        ("401 Unauthorized", false),
    ] {
        let (l, url) = listener().await;
        let (_, ack, _, _) = fixture(&url);
        let task = tokio::spawn(server(l, response(status, b"")));
        assert_eq!(
            DirectApi::new(&url)
                .unwrap()
                .ack("synthetic-token", &ack)
                .await
                .is_ok(),
            ok
        );
        task.await.unwrap();
    }
}
#[tokio::test]
async fn advertised_chunked_and_truncated_response_limits_fail_safely() {
    for mode in 0..3 {
        let (l, url) = listener().await;
        let (batch, _, _, _) = fixture(&url);
        let wire = match mode {
            0 => response("200 OK", &vec![b' '; 32769]),
            1 => {
                let mut wire=b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n8001\r\n".to_vec();
                wire.extend(vec![b' '; 32769]);
                wire.extend_from_slice(b"\r\n0\r\n\r\n");
                wire
            }
            _ => b"HTTP/1.1 200 OK\r\nContent-Length: 500\r\nConnection: close\r\n\r\n{}".to_vec(),
        };
        let task = tokio::spawn(server(l, wire));
        assert!(DirectApi::new(&url)
            .unwrap()
            .lookup("synthetic-token", &batch)
            .await
            .is_err());
        task.await.unwrap();
    }
}
#[tokio::test]
async fn malformed_local_ids_tokens_and_origins_never_start_a_request() {
    let (l, url) = listener().await;
    let (mut batch, _, _, _) = fixture(&url);
    let api = DirectApi::new(&url).unwrap();
    assert!(api.lookup("", &batch).await.is_err());
    assert!(api.lookup("bad\r\nheader", &batch).await.is_err());
    batch.header.id = "../other".into();
    assert!(api.publish("synthetic-token", &batch).await.is_err());
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(30), l.accept())
            .await
            .is_err()
    );
}
