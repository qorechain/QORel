use std::env;

use git::Handle as GitHandle;

fn main() {
    // Overwrites the package `version` with the QORel release version (plus git metadata), and
    // package `name` with 'qorel' (the binary name), instead of 'ibc-relayer-cli' (the crate
    // name), so that abscissa outputs consistent usage and help messages.
    // https://github.com/informalsystems/hermes/issues/590
    // Note: This can potentially break the normal cargo (or crates.io) workflow.
    println!("cargo:rustc-env=CARGO_PKG_NAME=qorel");
    println!("cargo:rustc-env=CARGO_PKG_VERSION={}", version());
}

// The QORel release version lives in `QOREL_VERSION` at the workspace root; the crate keeps the
// upstream Hermes version it is based on.
fn qorel_version() -> String {
    println!("cargo:rerun-if-changed=../../QOREL_VERSION");
    std::fs::read_to_string("../../QOREL_VERSION")
        .map(|v| v.trim().to_string())
        .unwrap_or_else(|_| env::var("CARGO_PKG_VERSION").unwrap())
}

// returns a valid semver string optionally suffixed with the current git branch and last commit
// hash. e.g. 0.4.0 or 0.4.0+cli-git-hash-eb0e94fc-dirty
fn version() -> String {
    let mut vers = qorel_version();
    if !is_ci_release() {
        if let Some(git) = GitHandle::new() {
            // Paths are relative to this crate; HEAD moves on checkout, the
            // branch refs on every commit.
            println!("cargo:rerun-if-changed=../../.git/HEAD");
            println!("cargo:rerun-if-changed=../../.git/refs/heads");
            println!("cargo:rerun-if-changed=../../.git/packed-refs");
            vers.push('+');
            vers.push_str(&git.last_commit_hash());
            if git.is_dirty() {
                vers.push_str("-dirty");
            }
            vers = vers.replace('\n', "");
        }
    }
    vers
}

fn is_ci_release() -> bool {
    println!("cargo:rerun-if-env-changed=QOREL_RELEASE");
    env::var("QOREL_RELEASE").is_ok_and(|v| v == "1")
}

mod git {
    use core::marker::PhantomData;
    use std::ffi::OsStr;
    use std::process::{Command, Output};

    // A wrapper over a git shell command that is only constructable if git is available & the
    // current directory is a git repository
    pub struct Handle(PhantomData<Command>);

    impl Handle {
        pub fn new() -> Option<Self> {
            if Self::is_git_repo() {
                Some(Handle(PhantomData))
            } else {
                None
            }
        }

        // Returns the short hash of the last git commit
        pub fn last_commit_hash(&self) -> String {
            let commit = Self::command(["rev-parse", "--short", "HEAD"]);
            String::from_utf8_lossy(&commit.stdout).into_owned()
        }

        // Checks if the git repo is dirty
        pub fn is_dirty(&self) -> bool {
            !Self::command(["diff-index", "--quiet", "HEAD", "--"])
                .status
                .success()
        }

        #[inline]
        fn command(args: impl IntoIterator<Item = impl AsRef<OsStr>>) -> Output {
            Command::new("git").args(args).output().unwrap()
        }

        // returns true iff git is installed and current directory is a git repo
        fn is_git_repo() -> bool {
            Command::new("git")
                .args(["rev-parse", "--git-dir"])
                .output()
                .is_ok_and(|o| o.status.success())
        }
    }
}
