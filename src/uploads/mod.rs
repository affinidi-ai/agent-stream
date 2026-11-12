//! Generic storage-backed image uploads.
//!
//! Provides a reusable multipart image extractor shared by the user-avatar
//! endpoint and the generic dashboard asset endpoint (LLM provider logos,
//! etc.). Files are written under a configured `_storage` directory and served
//! back as static assets, so the server never writes uploads into the bundled
//! `www` folder.

use axum::extract::Multipart;
use axum::{Extension, Json, http::StatusCode};
use serde::Serialize;
use tokio::fs;
use tokio::io::AsyncWriteExt;

/// Maximum accepted upload size (5 MiB).
pub const MAX_UPLOAD_SIZE: usize = 5 * 1024 * 1024;

/// Newtype wrapper so the uploads directory can be injected as an axum
/// `Extension` without colliding with other `String` extensions.
#[derive(Clone)]
pub struct UploadsDir(pub String);

/// Response body for [`upload_image`].
#[derive(Serialize)]
pub struct UploadResponse {
    /// Path relative to the served root, e.g. `uploads/<id>.png`.
    pub path: String,
}

/// Map a raster image content-type to a file extension. Returns `None` for
/// unsupported types. SVG is intentionally excluded: serving attacker-supplied
/// SVG from our own origin is a stored-XSS vector.
pub fn image_extension(content_type: &str) -> Option<&'static str> {
    match content_type {
        "image/jpeg" | "image/jpg" => Some("jpg"),
        "image/png" => Some("png"),
        "image/gif" => Some("gif"),
        "image/webp" => Some("webp"),
        _ => None,
    }
}

/// Verify the raw `bytes` actually start with the magic-number signature of the
/// raster format implied by `extension`. The multipart `Content-Type` is
/// attacker-controlled, so we never trust it alone to decide what we persist
/// and serve back. Returns `false` when the payload does not match.
pub fn bytes_match_extension(
    extension: &str,
    bytes: &[u8],
) -> bool {
    match extension {
        // JPEG: FF D8 FF
        "jpg" => bytes.starts_with(&[0xFF, 0xD8, 0xFF]),
        // PNG: 89 50 4E 47 0D 0A 1A 0A
        "png" => bytes.starts_with(&[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]),
        // GIF: "GIF87a" or "GIF89a"
        "gif" => bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a"),
        // WebP: "RIFF" .... "WEBP"
        "webp" => bytes.len() >= 12 && &bytes[0..4] == b"RIFF" && &bytes[8..12] == b"WEBP",
        _ => false,
    }
}

/// Read the first matching file field from `multipart`, validating it is a
/// supported raster image within the size limit. Returns the raw bytes and the
/// resolved file extension.
pub async fn read_image_field(
    multipart: &mut Multipart,
    field_name: &str,
) -> Result<(Vec<u8>, &'static str), (StatusCode, String)> {
    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Failed to read multipart field: {}", e)))?
    {
        if field.name() != Some(field_name) {
            continue;
        }

        let content_type = field
            .content_type()
            .unwrap_or("")
            .to_string();
        let extension = image_extension(&content_type).ok_or_else(|| {
            (
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                format!("Unsupported image type '{}'. Allowed: JPG, PNG, GIF, WebP", content_type),
            )
        })?;

        let bytes = field
            .bytes()
            .await
            .map_err(|e| (StatusCode::BAD_REQUEST, format!("Failed to read file data: {}", e)))?;
        if bytes.len() > MAX_UPLOAD_SIZE {
            return Err((StatusCode::PAYLOAD_TOO_LARGE, "Image size must be less than 5MB".to_string()));
        }

        if !bytes_match_extension(extension, &bytes) {
            return Err((
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "File content does not match a supported image format (JPG, PNG, GIF, WebP)".to_string(),
            ));
        }

        return Ok((bytes.to_vec(), extension));
    }

    Err((StatusCode::BAD_REQUEST, format!("No '{}' file provided", field_name)))
}

/// The static extension for one of the extensions `image_extension` returns.
fn image_extension_name(extension: &str) -> Option<&'static str> {
    match extension {
        "jpg" => Some("jpg"),
        "png" => Some("png"),
        "gif" => Some("gif"),
        "webp" => Some("webp"),
        _ => None,
    }
}

/// True when `name` is one normal path component: not empty, not `.` or `..`, with no separator.
fn is_single_path_component(name: &str) -> bool {
    let mut components = std::path::Path::new(name).components();
    matches!(
        (components.next(), components.next()),
        (Some(std::path::Component::Normal(part)), None) if part == std::ffi::OsStr::new(name)
    )
}

/// Persist image `bytes` into `dir` as `<file_stem>.<extension>` and return the
/// path relative to the served root (`<relative_prefix>/<file>`).
pub async fn save_image(
    dir: &str,
    relative_prefix: &str,
    file_stem: &str,
    extension: &str,
    bytes: &[u8],
) -> Result<String, (StatusCode, String)> {
    let extension = image_extension_name(extension)
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "Unsupported image extension".to_string()))?;
    if !is_single_path_component(file_stem) {
        return Err((StatusCode::BAD_REQUEST, "Invalid file name".to_string()));
    }

    fs::create_dir_all(dir)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to create upload directory: {}", e)))?;

    let filename = format!("{}.{}", file_stem, extension);
    let full_path = std::path::Path::new(dir).join(&filename);
    let mut file = fs::File::create(&full_path)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to create file: {}", e)))?;
    file.write_all(bytes)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to write file: {}", e)))?;
    file.flush()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to flush file: {}", e)))?;

    Ok(format!("{}/{}", relative_prefix, filename))
}

/// `POST /api/v1/uploads/image` — store an uploaded image under the configured
/// uploads directory and return its served path. Used for LLM provider logos
/// and other dashboard assets.
pub async fn upload_image(
    Extension(uploads_dir): Extension<UploadsDir>,
    mut multipart: Multipart,
) -> Result<Json<UploadResponse>, (StatusCode, String)> {
    let (bytes, extension) = read_image_field(&mut multipart, "file").await?;
    let id = uuid::Uuid::new_v4().to_string();
    let path = save_image(&uploads_dir.0, "uploads", &id, extension, &bytes).await?;
    Ok(Json(UploadResponse { path }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn image_extension_maps_supported_types() {
        assert_eq!(image_extension("image/png"), Some("png"));
        assert_eq!(image_extension("image/jpeg"), Some("jpg"));
        assert_eq!(image_extension("image/jpg"), Some("jpg"));
        assert_eq!(image_extension("image/gif"), Some("gif"));
        assert_eq!(image_extension("image/webp"), Some("webp"));
    }

    #[test]
    fn image_extension_rejects_svg_and_unknown() {
        assert_eq!(image_extension("image/svg+xml"), None);
        assert_eq!(image_extension("text/html"), None);
        assert_eq!(image_extension(""), None);
    }

    #[test]
    fn bytes_match_extension_accepts_valid_signatures() {
        assert!(bytes_match_extension("jpg", &[0xFF, 0xD8, 0xFF, 0xE0, 0x00]));
        assert!(bytes_match_extension("png", &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00]));
        assert!(bytes_match_extension("gif", b"GIF89a....."));
        assert!(bytes_match_extension("gif", b"GIF87a....."));
        assert!(bytes_match_extension("webp", b"RIFF\x00\x00\x00\x00WEBPVP8 "));
    }

    #[test]
    fn bytes_match_extension_rejects_mismatched_or_spoofed_content() {
        assert!(!bytes_match_extension("png", b"<script>alert(1)</script>"));
        assert!(!bytes_match_extension("webp", b"RIFF"));
        assert!(!bytes_match_extension("jpg", &[0x89, 0x50, 0x4E, 0x47]));
        assert!(!bytes_match_extension("png", &[]));
        assert!(!bytes_match_extension("svg", b"GIF89a"));
    }

    #[tokio::test]
    async fn save_image_writes_file_and_returns_relative_path() {
        let dir = std::env::temp_dir().join(format!("uploads_test_{}", uuid::Uuid::new_v4()));
        let dir_str = dir
            .to_string_lossy()
            .to_string();
        let bytes = [0x89, 0x50, 0x4E, 0x47];

        let path = save_image(&dir_str, "uploads", "logo", "png", &bytes)
            .await
            .expect("save_image should succeed");

        assert_eq!(path, "uploads/logo.png");
        let written = std::fs::read(dir.join("logo.png")).expect("file should exist");
        assert_eq!(written, bytes);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn save_image_refuses_a_file_name_that_leaves_the_directory() {
        let dir = std::env::temp_dir().join(format!("uploads_test_{}", uuid::Uuid::new_v4()));
        let dir_str = dir
            .to_string_lossy()
            .to_string();

        for stem in ["", ".", "..", "../escape", "a/b", "/abs"] {
            let result = save_image(&dir_str, "uploads", stem, "png", &[0x89]).await;
            match result {
                Err((status, _)) => assert_eq!(status, StatusCode::BAD_REQUEST, "stem {stem:?}"),
                Ok(path) => panic!("stem {stem:?} was accepted as {path}"),
            }
        }
        assert!(!dir.exists(), "nothing is created for a refused name");
    }

    #[tokio::test]
    async fn save_image_refuses_an_extension_that_is_not_an_image_type() {
        let dir = std::env::temp_dir().join(format!("uploads_test_{}", uuid::Uuid::new_v4()));
        let dir_str = dir
            .to_string_lossy()
            .to_string();

        for extension in ["svg", "png/../x", "", "html"] {
            let result = save_image(&dir_str, "uploads", "logo", extension, &[0x89]).await;
            assert!(matches!(result, Err((StatusCode::BAD_REQUEST, _))), "extension {extension:?} was accepted");
        }
        assert!(!dir.exists());
    }

    #[test]
    fn a_user_id_with_dots_and_at_signs_is_one_path_component() {
        assert!(is_single_path_component("jane.doe@example.com"));
        assert!(is_single_path_component("oidc-12"));
    }
}
