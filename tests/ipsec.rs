mod common;

#[tokio::test]
async fn upload_succeeds() {
    common::files::upload_success("ipsec/files/upload").await;
}

#[tokio::test]
async fn invalid_uploads_leave_files_unchanged() {
    common::files::upload_validation("ipsec/files/upload").await;
}

#[tokio::test]
async fn removal_is_idempotent() {
    common::files::remove_success("ipsec/files/remove").await;
}

#[tokio::test]
async fn invalid_removals_leave_files_unchanged() {
    common::files::remove_validation("ipsec/files/remove").await;
}

#[tokio::test]
async fn authorization_prevents_side_effects() {
    common::files::authorization("ipsec/files/upload", Some("ipsec/files/remove")).await;
}
