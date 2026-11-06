use super::{protected_options, spawn_app, TestApp, API_KEY};
use reqwest::{
    multipart::{Form, Part},
    Method, StatusCode,
};
use std::{
    fs,
    os::unix::fs::{symlink, PermissionsExt},
    path::Path,
};

pub fn form(dir: &Path, name: &str, contents: &str) -> Form {
    Form::new()
        .text("dst_dir", dir.to_str().unwrap().to_owned())
        .text("perms", "600")
        .part(
            "data",
            Part::text(contents.to_owned()).file_name(name.to_owned()),
        )
}

pub fn json_request(
    app: &TestApp,
    method: Method,
    endpoint: &str,
    body: serde_json::Value,
) -> reqwest::RequestBuilder {
    app.client()
        .request(method, format!("{app}/api/v1/{endpoint}"))
        .header("X-API-Key", API_KEY)
        .header("Content-Type", "application/json")
        .body(body.to_string())
}

// Includes staging and runtime paths, and never follows links used as attack fixtures.
pub fn snapshot(root: &Path) -> Vec<(String, Vec<u8>, u32)> {
    fn visit(root: &Path, dir: &Path, result: &mut Vec<(String, Vec<u8>, u32)>) {
        for entry in fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            let metadata = fs::symlink_metadata(&path).unwrap();
            let content = if metadata.file_type().is_symlink() {
                fs::read_link(&path)
                    .unwrap()
                    .as_os_str()
                    .as_encoded_bytes()
                    .to_vec()
            } else if metadata.is_file() {
                fs::read(&path).unwrap()
            } else {
                vec![]
            };
            result.push((
                path.strip_prefix(root).unwrap().to_str().unwrap().into(),
                content,
                metadata.permissions().mode(),
            ));
            if metadata.is_dir() {
                visit(root, &path, result);
            }
        }
    }
    let mut result = vec![];
    visit(root, root, &mut result);
    result.sort();
    result
}

pub async fn upload_success(endpoint: &str) {
    let app = spawn_app(Some(protected_options(true)));
    let dst = app.path("destination/nested");
    let response = app
        .client()
        .post(format!("{app}/api/v1/{endpoint}"))
        .header("X-API-Key", API_KEY)
        .multipart(form(&dst, "vpn.conf", "isolated configuration\n"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.text().await.unwrap(), "");
    assert_eq!(
        fs::read_to_string(dst.join("vpn.conf")).unwrap(),
        "isolated configuration\n"
    );
    assert_eq!(
        fs::metadata(dst.join("vpn.conf"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    // Overwrite an existing destination and verify its new contents.
    let response = app
        .client()
        .post(format!("{app}/api/v1/{endpoint}"))
        .header("X-API-Key", API_KEY)
        .multipart(form(&dst, "vpn.conf", "replacement\n"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        fs::read_to_string(dst.join("vpn.conf")).unwrap(),
        "replacement\n"
    );
    assert_eq!(fs::read_dir(app.path("tmp")).unwrap().count(), 0);
    assert!(app.commands.calls.lock().unwrap().is_empty());
}

pub async fn upload_validation(endpoint: &str) {
    let app = spawn_app(Some(protected_options(true)));
    let dst = app.path("destination");
    fs::create_dir(&dst).unwrap();
    fs::write(dst.join("vpn.conf"), "original").unwrap();
    fs::write(app.path("sentinel"), "outside destination").unwrap();
    symlink(app.path("sentinel"), dst.join("link.conf")).unwrap();
    symlink(app.path("etc"), app.path("linked-dir")).unwrap();
    let before = snapshot(app.root.path());
    let url = format!("{app}/api/v1/{endpoint}");
    let requests = vec![
        app.client().post(&url),
        app.client().post(&url).multipart(Form::new()),
        app.client().post(&url).multipart(Form::new().part("data", Part::text("new").file_name("vpn.conf"))),
        app.client().post(&url).multipart(Form::new().text("dst_dir", dst.to_str().unwrap().to_owned())),
        app.client().post(&url).multipart(form(&app.path("sentinel"), "vpn.conf", "new")),
        app.client().post(&url).multipart(form(&app.path("destination/../escape"), "vpn.conf", "new")),
        app.client().post(&url).multipart(form(&app.path("linked-dir"), "vpn.conf", "new")),
        app.client().post(&url).multipart(form(&dst, "../sentinel", "new")),
        app.client().post(&url).multipart(form(&dst, "/sentinel", "new")),
        app.client().post(&url).multipart(form(&dst, "bad\\name", "new")),
        app.client().post(&url).multipart(form(&dst, "link.conf", "new")),
        app.client().post(&url).multipart(form(&dst, "", "new")),
        app.client().post(&url).multipart(form(&dst, "vpn.conf", "new").text("perms", "999")),
        app.client().post(&url).multipart(form(&dst, "vpn.conf", "new").text("unexpected", "value")),
        app.client().post(&url).multipart(form(&app.path("must-not-be-created"), "vpn.conf", "new").text("ws_id", "invalid")),
        app.client().post(&url).header("Content-Type", "multipart/form-data; boundary=test")
            .body("--test\r\nContent-Disposition: form-data; name=\"dst_dir\"\r\n\r\ntruncated"),
        app.client().post(&url).header("Content-Type", "multipart/form-data; boundary=test")
            .body("--test\r\nContent-Type: text/plain\r\n\r\nmissing metadata\r\n--test--\r\n"),
        // A complete staged file followed by a broken part must not commit earlier files.
        app.client().post(&url).header("Content-Type", "multipart/form-data; boundary=test").body(format!(
            "--test\r\nContent-Disposition: form-data; name=\"dst_dir\"\r\n\r\n{}\r\n--test\r\nContent-Disposition: form-data; name=\"data\"; filename=\"vpn.conf\"\r\n\r\nnew\r\n--test\r\nbroken", dst.display())),
    ];
    for (index, request) in requests.into_iter().enumerate() {
        let response = request.header("X-API-Key", API_KEY).send().await.unwrap();
        let status = response.status();
        let body = response.text().await.unwrap();
        assert_eq!(status, StatusCode::BAD_REQUEST, "case {index}: {body}");
        assert_eq!(
            snapshot(app.root.path()),
            before,
            "case {index} changed files"
        );
        assert!(app.commands.calls.lock().unwrap().is_empty());
    }
}

pub async fn remove_success(endpoint: &str) {
    let app = spawn_app(Some(protected_options(true)));
    let dst = app.path("destination");
    fs::create_dir(&dst).unwrap();
    fs::write(dst.join("vpn.conf"), "remove me").unwrap();
    fs::write(dst.join("keep.conf"), "preserved").unwrap();
    for _ in 0..2 {
        // Nonexistent files are intentionally idempotent.
        let response = json_request(
            &app,
            Method::DELETE,
            endpoint,
            serde_json::json!({"dir": dst, "files": ["vpn.conf"]}),
        )
        .send()
        .await
        .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.text().await.unwrap(), "");
        assert!(!dst.join("vpn.conf").exists());
        assert_eq!(
            fs::read_to_string(dst.join("keep.conf")).unwrap(),
            "preserved"
        );
    }
    assert!(app.commands.calls.lock().unwrap().is_empty());
}

pub async fn remove_validation(endpoint: &str) {
    let app = spawn_app(Some(protected_options(true)));
    let dst = app.path("destination");
    fs::create_dir(&dst).unwrap();
    fs::write(dst.join("keep.conf"), "preserved").unwrap();
    fs::write(app.path("sentinel"), "outside destination").unwrap();
    symlink(app.path("sentinel"), dst.join("link.conf")).unwrap();
    symlink(&dst, app.path("linked-dir")).unwrap();
    let before = snapshot(app.root.path());
    let url = format!("{app}/api/v1/{endpoint}");
    for body in [
        "",
        "{",
        "{}",
        "{\"dir\":1,\"files\":[]}",
        "{\"dir\":\"unused\",\"files\":\"invalid\"}",
    ] {
        let response = app
            .client()
            .delete(&url)
            .header("X-API-Key", API_KEY)
            .header("Content-Type", "application/json")
            .body(body)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(snapshot(app.root.path()), before);
    }
    let response = app
        .client()
        .delete(&url)
        .header("X-API-Key", API_KEY)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    for (dir, files) in [
        (dst.clone(), vec!["keep.conf", "../sentinel"]), // Validate the entire batch before deleting.
        (dst.clone(), vec!["/sentinel"]),
        (dst.clone(), vec!["bad\\name"]),
        (dst.clone(), vec![""]),
        (dst.clone(), vec!["."]),
        (dst.clone(), vec!["link.conf"]),
        (app.path("destination/.."), vec!["sentinel"]),
        (app.path("missing"), vec!["vpn.conf"]),
        (app.path("sentinel"), vec!["vpn.conf"]),
        (app.path("linked-dir"), vec!["keep.conf"]),
    ] {
        let response = json_request(
            &app,
            Method::DELETE,
            endpoint,
            serde_json::json!({"dir": dir, "files": files}),
        )
        .send()
        .await
        .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(snapshot(app.root.path()), before);
    }
    assert!(app.commands.calls.lock().unwrap().is_empty());
}

pub async fn authorization(upload: &str, remove: Option<&str>) {
    for (allowed, key, message) in [
        (true, None, "API key not found"),
        (true, Some("invalid"), "Invalid API key"),
        (
            false,
            Some(API_KEY),
            "Authorization error, access from your IP is not allowed",
        ),
    ] {
        let app = spawn_app(Some(protected_options(allowed)));
        let dst = app.path("destination");
        fs::create_dir(&dst).unwrap();
        fs::write(dst.join("vpn.conf"), "preserved").unwrap();
        let before = snapshot(app.root.path());
        let mut requests = vec![app
            .client()
            .post(format!("{app}/api/v1/{upload}"))
            .multipart(form(&dst, "vpn.conf", "unauthorized"))];
        if let Some(remove) = remove {
            requests.push(
                app.client()
                    .delete(format!("{app}/api/v1/{remove}"))
                    .header("Content-Type", "application/json")
                    .body(serde_json::json!({"dir":dst,"files":["vpn.conf"]}).to_string()),
            );
        }
        for mut request in requests {
            if let Some(key) = key {
                request = request.header("X-API-Key", key);
            }
            let response = request.send().await.unwrap();
            assert_eq!(response.status(), StatusCode::FORBIDDEN);
            assert_eq!(
                serde_json::from_str::<serde_json::Value>(&response.text().await.unwrap()).unwrap()
                    ["message"],
                message
            );
            assert_eq!(snapshot(app.root.path()), before);
            assert!(app.commands.calls.lock().unwrap().is_empty());
        }
    }
}
