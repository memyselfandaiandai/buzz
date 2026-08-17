use buzz_workspace_controller::{
    AdmissionOutcome, AdmissionRequest, ControllerError, Ledger, Scope,
};
use std::path::Path;
use std::process::{Command, ExitCode};
use std::time::{Duration, Instant};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("admit") => admit(&args),
        Some("cancel") => cancel(&args),
        Some("heartbeat-parent") => heartbeat_parent(&args),
        Some("heartbeat-child") => heartbeat_child(&args),
        _ => {
            eprintln!("unsupported local controller fixture command");
            ExitCode::from(64)
        }
    }
}

fn admit(args: &[String]) -> ExitCode {
    if args.len() != 10 {
        return ExitCode::from(64);
    }
    let signed = match args[7].parse::<u32>() {
        Ok(value) => value,
        Err(_) => return ExitCode::from(64),
    };
    let deployment = match args[8].parse::<u32>() {
        Ok(value) => value,
        Err(_) => return ExitCode::from(64),
    };
    let scope = match args[5].as_str() {
        "agent" => Scope::Agent(args[6].clone()),
        "tenant" => Scope::Tenant(args[6].clone()),
        "issuer" => Scope::Issuer(args[6].clone()),
        _ => return ExitCode::from(64),
    };
    if !wait_for_barrier(Path::new(&args[9])) {
        return ExitCode::from(70);
    }
    let request = AdmissionRequest {
        session_id: args[2].clone(),
        jti: args[3].clone(),
        capability_digest: format!("sha256:{}", args[3]),
        owner_id: "agent:local-fixture".into(),
        workspace_id: args[4].clone(),
        scope,
        signed_max_concurrency: signed,
        deployment_max_concurrency: deployment,
        artifact_limit_bytes: 1_000_000,
        expires_at: 2_000_000_000,
    };
    let ledger = match Ledger::open(&args[1]) {
        Ok(ledger) => ledger,
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::from(70);
        }
    };
    match ledger.prepare_and_admit(&request) {
        Ok(AdmissionOutcome::Admitted) => ExitCode::SUCCESS,
        Ok(AdmissionOutcome::Existing(_)) => ExitCode::from(10),
        Err(ControllerError::CapacityExceeded { .. }) => ExitCode::from(20),
        Err(
            ControllerError::JtiReplay
            | ControllerError::CapabilityReplay
            | ControllerError::WorkspaceOwned
            | ControllerError::SessionConflict,
        ) => ExitCode::from(21),
        Err(error) => {
            eprintln!("{error}");
            ExitCode::from(70)
        }
    }
}

fn cancel(args: &[String]) -> ExitCode {
    if args.len() != 3 {
        return ExitCode::from(64);
    }
    let result = Ledger::open(&args[1])
        .and_then(|ledger| ledger.request_cancellation(&args[2], "external local cancellation"));
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::from(70)
        }
    }
}

fn heartbeat_parent(args: &[String]) -> ExitCode {
    if args.len() != 3 {
        return ExitCode::from(64);
    }
    let executable = match std::env::current_exe() {
        Ok(path) => path,
        Err(_) => return ExitCode::from(70),
    };
    if Command::new(executable)
        .args(["heartbeat-child", &args[2]])
        .spawn()
        .is_err()
    {
        return ExitCode::from(70);
    }
    heartbeat_forever(Path::new(&args[1]))
}

fn heartbeat_child(args: &[String]) -> ExitCode {
    if args.len() != 2 {
        return ExitCode::from(64);
    }
    heartbeat_forever(Path::new(&args[1]))
}

fn heartbeat_forever(path: &Path) -> ! {
    let mut counter = 0_u64;
    loop {
        counter += 1;
        let _ = std::fs::write(path, format!("{}:{counter}", std::process::id()));
        std::thread::sleep(Duration::from_millis(25));
    }
}

fn wait_for_barrier(path: &Path) -> bool {
    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline {
        if path.exists() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    false
}
