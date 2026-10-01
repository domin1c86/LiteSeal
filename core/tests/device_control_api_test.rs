use liteseal_core::trusted_devices::api::DeviceControlApi;
use liteseal_shared::trusted_device::MAX_DEVICE_PAGE_BYTES;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};
async fn response(headers: String, body: Vec<u8>) -> (String, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buffer = vec![0; 4096];
        let _ = stream.read(&mut buffer).await;
        let _ = stream.write_all(headers.as_bytes()).await;
        let _ = stream.write_all(&body).await;
    });
    (url, task)
}
#[tokio::test]
async fn control_api_refuses_redirect_and_never_forwards_credentials() {
    let sink = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let headers=format!("HTTP/1.1 302 Found\r\nLocation: http://{}/devices/join_requests/test\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",sink.local_addr().unwrap());
    let (url, task) = response(headers, vec![]).await;
    let api = DeviceControlApi::new(&url).unwrap();
    let error = api
        .status("isolated-secret", &uuid::Uuid::new_v4().to_string(), None)
        .await
        .unwrap_err();
    assert_eq!(error.status, Some(302));
    assert!(!error.to_string().contains("isolated-secret"));
    task.await.unwrap();
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(50), sink.accept())
            .await
            .is_err()
    );
}
#[tokio::test]
async fn control_api_rejects_oversized_and_untyped_responses_without_leaking_body() {
    let headers=format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",MAX_DEVICE_PAGE_BYTES+1);
    let (url, task) = response(headers, vec![]).await;
    assert!(DeviceControlApi::new(&url)
        .unwrap()
        .status("isolated-token", &uuid::Uuid::new_v4().to_string(), None)
        .await
        .is_err());
    task.await.unwrap();
    let body = b"{\"untrusted_token\":\"must-not-leak\"}".to_vec();
    let headers=format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",body.len());
    let (url, task) = response(headers, body).await;
    let error = DeviceControlApi::new(&url)
        .unwrap()
        .status("isolated-token", &uuid::Uuid::new_v4().to_string(), None)
        .await
        .unwrap_err();
    assert!(!error.to_string().contains("must-not-leak"));
    task.await.unwrap();
    assert!(DeviceControlApi::new("https://relay.example/private").is_err());
    assert!(DeviceControlApi::new("https://user:password@relay.example").is_err());
}
