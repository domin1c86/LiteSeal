use liteseal_core::trusted_devices::messages::api::{DirectApi, MediaObject, RemoteState};
use liteseal_shared::{
    crypto,
    direct_media::{Descriptor, Reference, Submission, CHUNK},
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

fn media_fixture(origin: &str) -> Submission {
    let keys = crypto::generate_keypair().unwrap();
    let peer_keys = crypto::generate_keypair().unwrap();
    let state = |keys: &crypto::KeyPair| {
        DeviceState::pin(Anchor {
            origin: origin.into(),
            account: uuid::Uuid::new_v4().to_string(),
            root: DeviceIdentity::from_keys(uuid::Uuid::new_v4().to_string(), keys),
        })
        .unwrap()
    };
    let sender = state(&keys);
    let peer = state(&peer_keys);
    let object_id = uuid::Uuid::new_v4().to_string();
    let (descriptor, _) = Descriptor::encrypt(
        object_id.clone(),
        "秘密名称.txt".into(),
        b"synthetic",
        Kind::Attachment,
        None,
    )
    .unwrap();
    Submission::make(
        Header::new(
            &sender,
            &peer,
            &sender.anchor().root.device_id,
            MessageSpec {
                id: object_id,
                sequence: 1,
                previous: vec![],
                sent_at: 1,
                kind: Kind::Attachment,
            },
        )
        .unwrap(),
        &sender,
        &peer,
        &keys,
        &descriptor,
    )
    .unwrap()
}

fn body(request: &[u8]) -> &[u8] {
    let end = request.windows(4).position(|v| v == b"\r\n\r\n").unwrap();
    &request[end + 4..]
}

#[tokio::test]
async fn media_create_binds_returned_id_and_upload_requires_exact_no_content() {
    for mode in 0..4 {
        let (l, url) = listener().await;
        let value = media_fixture(&url);
        let object = MediaObject {
            device: &value.batch.header.sender_device,
            id: &value.batch.header.id,
            reference: &value.object,
        };
        let returned = if mode == 1 {
            uuid::Uuid::new_v4().to_string()
        } else {
            object.id.to_owned()
        };
        let wire = if mode < 2 {
            response("200 OK", &serde_json::to_vec(&returned).unwrap())
        } else {
            response(
                if mode == 2 {
                    "204 No Content"
                } else {
                    "200 OK"
                },
                b"",
            )
        };
        let task = tokio::spawn(server(l, wire));
        let api = DirectApi::new(&url).unwrap();
        let result = if mode < 2 {
            api.create_media(
                "synthetic-token",
                object.device,
                object.id,
                &value.batch.header.peer,
                object.reference,
            )
            .await
        } else {
            api.upload_media_chunk(
                "synthetic-token",
                &object,
                0,
                vec![5; object.reference.size as usize],
            )
            .await
        };
        assert_eq!(result.is_ok(), mode == 0 || mode == 2);
        let request = task.await.unwrap();
        if mode < 2 {
            let fields: serde_json::Value = serde_json::from_slice(body(&request)).unwrap();
            assert_eq!(fields.as_object().unwrap().len(), 5);
            assert_eq!(fields["id"], object.id);
            assert!(fields.get("key").is_none());
            assert!(fields.get("name").is_none());
        } else {
            assert_eq!(body(&request), vec![5; object.reference.size as usize]);
            assert!(String::from_utf8_lossy(&request).starts_with(&format!(
                "PUT /direct/v3/media/objects/{}/0?device_id={} ",
                object.id, object.device
            )));
        }
    }
}

#[tokio::test]
async fn media_tail_chunk_rejects_wrong_length_chunked_overflow_and_truncation() {
    for mode in 0..5 {
        let (l, url) = listener().await;
        let value = media_fixture(&url);
        let reference = Reference {
            size: CHUNK as u64 + 40,
            hash: [7; 32],
        };
        let object = MediaObject {
            device: &value.batch.header.sender_device,
            id: &value.batch.header.id,
            reference: &reference,
        };
        let wire = match mode {
            0 => response("200 OK", &[9; 40]),
            1 => response("200 OK", &[9; 41]),
            2 => response("200 OK", &[9; 39]),
            3 => {
                let mut wire = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n29\r\n".to_vec();
                wire.extend_from_slice(&[9; 41]);
                wire.extend_from_slice(b"\r\n0\r\n\r\n");
                wire
            }
            _ => {
                b"HTTP/1.1 200 OK\r\nContent-Length: 40\r\nConnection: close\r\n\r\nshort".to_vec()
            }
        };
        let task = tokio::spawn(server(l, wire));
        let result = DirectApi::new(&url)
            .unwrap()
            .download_media_chunk("synthetic-token", &object, 1)
            .await;
        assert_eq!(result.is_ok(), mode == 0);
        if let Ok(bytes) = result {
            assert_eq!(bytes, vec![9; 40]);
        }
        task.await.unwrap();
    }
}

#[tokio::test]
async fn media_response_loss_retries_identical_wrapper_and_ciphertext() {
    let (l, url) = listener().await;
    let value = media_fixture(&url);
    let accepted = Outcome::Accepted {
        receipt: receipt(&value.batch),
        acknowledgements: vec![],
    };
    let valid = response("200 OK", &serde_json::to_vec(&accepted).unwrap());
    let task = tokio::spawn(async move {
        let first = serve_one(&l, vec![]).await;
        let second = serve_one(&l, valid).await;
        (first, second)
    });
    let api = DirectApi::new(&url).unwrap();
    assert!(api.publish_media("synthetic-token", &value).await.is_err());
    assert_eq!(
        api.publish_media("synthetic-token", &value)
            .await
            .unwrap()
            .state(),
        RemoteState::Accepted
    );
    let (first, second) = task.await.unwrap();
    assert_eq!(body(&first), body(&second));
    assert_eq!(body(&second), value.to_wire().unwrap());
    assert!(!second
        .windows("秘密名称.txt".len())
        .any(|s| s == "秘密名称.txt".as_bytes()));
}

#[tokio::test]
async fn media_publish_rejects_wrong_receipt_and_invalid_local_binding() {
    let (l, url) = listener().await;
    let value = media_fixture(&url);
    let mut wrong = receipt(&value.batch);
    wrong.digest[0] ^= 1;
    let response = response(
        "200 OK",
        &serde_json::to_vec(&Outcome::Accepted {
            receipt: wrong,
            acknowledgements: vec![],
        })
        .unwrap(),
    );
    let task = tokio::spawn(server(l, response));
    assert!(DirectApi::new(&url)
        .unwrap()
        .publish_media("synthetic-token", &value)
        .await
        .is_err());
    task.await.unwrap();
    let (l, foreign) = listener().await;
    assert!(DirectApi::new(&foreign)
        .unwrap()
        .publish_media("synthetic-token", &value)
        .await
        .is_err());
    let (local, local_url) = listener().await;
    let mut damaged = media_fixture(&local_url);
    damaged.object.hash[0] ^= 1;
    assert!(DirectApi::new(&local_url)
        .unwrap()
        .publish_media("synthetic-token", &damaged)
        .await
        .is_err());
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(30), l.accept())
            .await
            .is_err()
    );
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(30), local.accept())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn media_invalid_routes_parts_lengths_and_tokens_never_send() {
    let (l, url) = listener().await;
    let value = media_fixture(&url);
    let api = DirectApi::new(&url).unwrap();
    let mut object = MediaObject {
        device: &value.batch.header.sender_device,
        id: &value.batch.header.id,
        reference: &value.object,
    };
    for part in [-1, 1, 21, i32::MAX] {
        assert!(api
            .download_media_chunk("synthetic-token", &object, part)
            .await
            .is_err());
    }
    assert!(api
        .upload_media_chunk("synthetic-token", &object, 0, vec![0; 1])
        .await
        .is_err());
    assert!(api
        .download_media_chunk("bad\r\nheader", &object, 0)
        .await
        .is_err());
    object.id = "../foreign";
    assert!(api
        .download_media_chunk("synthetic-token", &object, 0)
        .await
        .is_err());
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(30), l.accept())
            .await
            .is_err()
    );
}
#[tokio::test]
async fn media_full_chunk_response_loss_and_redirect_keep_original_ciphertext_local() {
    let (l, url) = listener().await;
    let value = media_fixture(&url);
    let reference = Reference {
        size: CHUNK as u64 + 40,
        hash: [3; 32],
    };
    let object = MediaObject {
        device: &value.batch.header.sender_device,
        id: &value.batch.header.id,
        reference: &reference,
    };
    let task = tokio::spawn(async move {
        let first = serve_one(&l, vec![]).await;
        let second = serve_one(&l, response("204 No Content", b"")).await;
        (first, second)
    });
    let api = DirectApi::new(&url).unwrap();
    let cipher = vec![11; CHUNK];
    assert!(api
        .upload_media_chunk("synthetic-token", &object, 0, cipher.clone())
        .await
        .is_err());
    api.upload_media_chunk("synthetic-token", &object, 0, cipher.clone())
        .await
        .unwrap();
    let (first, second) = task.await.unwrap();
    assert_eq!(body(&first), cipher);
    assert_eq!(body(&first), body(&second));
    let (l, url) = listener().await;
    let (destination, destination_url) = listener().await;
    let task = tokio::spawn(server(l, format!("HTTP/1.1 307 Temporary Redirect\r\nLocation: {destination_url}/leak\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").into_bytes()));
    let error = DirectApi::new(&url)
        .unwrap()
        .upload_media_chunk("synthetic-token", &object, 0, cipher)
        .await
        .err()
        .unwrap();
    assert_eq!(error.status, Some(307));
    task.await.unwrap();
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(30), destination.accept())
            .await
            .is_err()
    );
}

async fn server(listener: TcpListener, response: Vec<u8>) -> Vec<u8> {
    serve_one(&listener, response).await
}
async fn serve_one(listener: &TcpListener, response: Vec<u8>) -> Vec<u8> {
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
