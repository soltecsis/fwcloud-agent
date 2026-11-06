mod common;

#[tokio::test]
async fn concurrent_apps_use_distinct_directories_and_clean_up_servers() {
    let first = common::spawn_app(None);
    let second = common::spawn_app(None);
    let first_root = first.root.path().to_owned();
    let second_root = second.root.path().to_owned();
    let first_address = first.address.clone();
    let second_address = second.address.clone();
    assert_ne!(first_root, second_root);
    assert_ne!(first_address, second_address);
    let (first_response, second_response) = tokio::join!(
        first
            .client()
            .post(format!("{first}/api/v1/daemon/config/upload"))
            .multipart(common::files::form(
                &first.path("destination"),
                "same.conf",
                "first"
            ))
            .send(),
        second
            .client()
            .post(format!("{second}/api/v1/daemon/config/upload"))
            .multipart(common::files::form(
                &second.path("destination"),
                "same.conf",
                "second"
            ))
            .send(),
    );
    assert_eq!(first_response.unwrap().status().as_u16(), 200);
    assert_eq!(second_response.unwrap().status().as_u16(), 200);
    assert_eq!(
        std::fs::read_to_string(first.path("destination/same.conf")).unwrap(),
        "first"
    );
    assert_eq!(
        std::fs::read_to_string(second.path("destination/same.conf")).unwrap(),
        "second"
    );
    drop(first);
    drop(second);
    assert!(!first_root.exists());
    assert!(!second_root.exists());
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(std::time::Duration::from_secs(1))
        .build()
        .unwrap();
    assert!(client
        .put(format!("{first_address}/api/v1/ping"))
        .send()
        .await
        .is_err());
    assert!(client
        .put(format!("{second_address}/api/v1/ping"))
        .send()
        .await
        .is_err());
}

#[tokio::test]
async fn fixture_cleanup_also_runs_when_a_test_panics() {
    let app = common::spawn_app(None);
    let root = app.root.path().to_owned();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
        let _app = app;
        panic!("exercise fixture cleanup");
    }));
    assert!(result.is_err());
    assert!(!root.exists());
}
