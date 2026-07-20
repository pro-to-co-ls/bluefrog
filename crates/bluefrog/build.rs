//! Embeds the version reported by `bluefrog --version`. In CI on a tag push it is the release tag
//! (`GITHUB_REF_NAME`); locally it is `git describe`; otherwise the crate version.

use std::process::Command;

fn main() {
    println!("cargo:rerun-if-env-changed=GITHUB_REF_NAME");
    println!("cargo:rustc-env=BLUEFROG_VERSION={}", version());
}

fn version() -> String {
    if let Ok(tag) = std::env::var("GITHUB_REF_NAME")
        && tag.starts_with('v')
        && tag.chars().nth(1).is_some_and(|c| c.is_ascii_digit())
    {
        return tag;
    }
    if let Ok(out) = Command::new("git")
        .args(["describe", "--tags", "--always", "--dirty"])
        .output()
        && out.status.success()
    {
        let described = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if !described.is_empty() {
            return described;
        }
    }
    std::env::var("CARGO_PKG_VERSION").unwrap_or_else(|_| "unknown".into())
}
