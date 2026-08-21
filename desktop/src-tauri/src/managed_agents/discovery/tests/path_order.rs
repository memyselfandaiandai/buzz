/// PATH directory order must win over extension preference. An npm `.cmd`
/// shim in an earlier directory is the intended command even if a later
/// directory contains an unrelated `.exe` with the same name.
#[test]
fn cmd_shim_in_earlier_path_dir_wins_over_later_exe() {
    let _guard = crate::managed_agents::lock_path_mutex();

    let earlier = tempfile::tempdir().expect("earlier tempdir");
    let later = tempfile::tempdir().expect("later tempdir");
    let shim = earlier.path().join("test-path-order.cmd");
    let exe = later.path().join("test-path-order.exe");
    std::fs::write(&shim, "@echo off\r\n").expect("write shim");
    std::fs::write(&exe, b"not a real executable").expect("write exe placeholder");

    let old_path = std::env::var_os("PATH").unwrap_or_default();
    let joined = std::env::join_paths([earlier.path(), later.path()]).expect("join PATH");
    std::env::set_var("PATH", &joined);

    let result = super::super::resolve_command_uncached("test-path-order");

    std::env::set_var("PATH", &old_path);
    assert_eq!(result.as_deref(), Some(shim.as_path()));
}
