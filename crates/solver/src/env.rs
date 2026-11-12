//! Optional recorded browser environment (`SolverEnv`) replay.

use crate::Result;

/// Load a snapshot produced by `tools/capture-env.js` (real Chrome).
pub fn load_device(path: &str) -> Result<serde_json::Value> {
    let raw = std::fs::read_to_string(path)?;
    let value: serde_json::Value = serde_json::from_str(&raw)?;
    native_payload::profile::DeviceProfile::from_capture_json(&value)
        .map_err(|msg| format!("{path}: {msg}"))?;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_object_snapshots() {
        let path = std::env::temp_dir().join("bad-solver-env.json");
        std::fs::write(&path, "[1,2,3]").unwrap();
        assert!(load_device(path.to_str().unwrap()).is_err());
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn accepts_capture_env_shape() {
        let path = std::env::temp_dir().join("good-solver-env.json");
        std::fs::write(
            &path,
            r#"{"ua":"Mozilla/5.0","navigator":{"platform":"MacIntel"},"screen":{"width":1728},"window":{"innerWidth":1280}}"#,
        )
        .unwrap();
        let device = load_device(path.to_str().unwrap()).expect("loads");
        assert_eq!(
            device.get("ua").and_then(|v| v.as_str()),
            Some("Mozilla/5.0")
        );
        let _ = std::fs::remove_file(path);
    }
}
