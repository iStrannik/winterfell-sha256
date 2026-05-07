//! Прогон experiment_sha (SHA-256 AIR): измерение размера proof по длине трассы.
//!
//! Запуск (из корня репозитория):
//! ```text
//! cargo run -p examples --features std --bin sha256_proof_scaling -- [OUT_DIR]
//! cargo run -p examples --features std --bin sha256_proof_scaling -- --debug [OUT_DIR]
//! ```
//!
//! **Прод (по умолчанию):** $n=2^k$ для $k=13,\ldots,20$; для $k\le 18$ по `PROD_RUNS_MEDIUM_DEFAULT` (20) прогонов,
//! для $k\in\{19,20\}$ по `PROD_RUNS_LARGE_DEFAULT` (6). До $2^{20}$ включительно.
//!
//! **`--debug`:** только $k\in\{13,14,15\}$, по 20 прогонов на точку.
//!
//! Выход: `sha256_scaling_runs.csv`, `sha256_scaling_summary.csv`, `sha256_scaling_proof_size.png`, `README.txt`.

#[cfg(feature = "std")]
fn main() {
    use examples::experiment_sha::proof_scaling::{
        run_scaling, ScalingConfig, ScalingProfile,
    };
    use std::path::PathBuf;

    let mut out_dir = PathBuf::from("docs/experiment_sha_winterfell/scaling_data");
    let mut profile = ScalingProfile::prod_default();

    for arg in std::env::args().skip(1) {
        if arg == "--debug" {
            profile = ScalingProfile::debug_default();
        } else if !arg.starts_with('-') {
            out_dir = PathBuf::from(arg);
        } else {
            eprintln!("Неизвестный аргумент: {arg}. Используйте --debug и/или путь к каталогу вывода.");
            std::process::exit(2);
        }
    }

    let config = ScalingConfig {
        out_dir: out_dir.clone(),
        ..ScalingConfig::default()
    };

    eprintln!(
        "sha256_proof_scaling: каталог={}, режим={}",
        out_dir.display(),
        match profile {
            ScalingProfile::Prod { .. } => {
                "PROD (k=13..20; до k=18 по 20 прогонов, k=19,20 по 6)"
            }
            ScalingProfile::Debug { .. } => "DEBUG (k=13..15, по 20 прогонов)",
        }
    );

    if let Err(e) = run_scaling(config, profile) {
        eprintln!("sha256_proof_scaling: {e}");
        std::process::exit(1);
    }
}

#[cfg(not(feature = "std"))]
fn main() {
    eprintln!("sha256_proof_scaling requires feature std");
}
