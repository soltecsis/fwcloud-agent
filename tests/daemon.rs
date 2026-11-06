mod common;

#[tokio::test]
async fn upload_succeeds() {
    common::files::upload_success("daemon/config/upload").await;
}

#[tokio::test]
async fn invalid_uploads_leave_files_unchanged() {
    common::files::upload_validation("daemon/config/upload").await;
}

#[tokio::test]
async fn authorization_prevents_side_effects() {
    common::files::authorization("daemon/config/upload", None).await;
}
