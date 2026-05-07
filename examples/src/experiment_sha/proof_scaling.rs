//! Запуск experiment_sha (SHA-256 AIR) на разных длинах трассы: CSV + график (факт / ожидаемое / асимптотика).

use std::fs::{create_dir_all, File};
use std::io::Write;
use std::path::Path;

use plotters::prelude::*;
use winterfell::crypto::Hasher;
use winterfell::{BatchingMethod, FieldExtension, ProofOptions};

use crate::experiment_sha::table_constants::TABLE_WIDTH;
use crate::experiment_sha::utis::prepare_sha_256_block_bytes;
use crate::experiment_sha::vm_program::PROGRAM_LEN;
use crate::experiment_sha::ExperimentShaExample;
use crate::{Blake3_256, Example};

/// Число блоков SHA-256 после паддинга для сообщения из `msg_len` байт.
pub fn sha256_blocks_for_message_len(msg_len: usize) -> usize {
    let s = "a".repeat(msg_len);
    prepare_sha_256_block_bytes(&s).len() / 64
}

/// Длина трассы `experiment_sha`: `PROGRAM_LEN × (байты после паддинга / 64)`.
pub fn trace_length_for_message_len(msg_len: usize) -> usize {
    PROGRAM_LEN.saturating_mul(sha256_blocks_for_message_len(msg_len))
}

/// Минимальная степень $n=2^k$, достижимая для trace: $2^{13}$ ($n=\texttt{PROGRAM\_LEN}$ для одного SHA-блока).
/// Степени $2^{10},2^{11},2^{12}$ не кратны \texttt{PROGRAM\_LEN}${}=8192$, их не используем.
pub const SCALING_MIN_EXP: u32 = 13;

/// Отладочный верх: только $n\le 2^{15}$ (три точки: $2^{13},2^{14},2^{15}$).
pub const SCALING_MAX_EXP_DEBUG: u32 = 15;

/// Прод: максимальная степень $n=2^k$ (включительно), до $2^{20}$.
pub const SCALING_MAX_EXP_PROD: u32 = 20;

/// Степень $k$, начиная с которой в проде используется меньше прогонов ($2^{19}$, $2^{20}$).
pub const SCALING_PROD_LARGE_EXP_START: u32 = 19;

/// Число прогонов по умолчанию (прод): для $k\in[13,18]$.
pub const PROD_RUNS_MEDIUM_DEFAULT: usize = 20;

/// Число прогонов по умолчанию (прод): для $k\in\{19,20\}$.
pub const PROD_RUNS_LARGE_DEFAULT: usize = 6;

/// Режим масштабирования: быстрая отладка или полный прод до $2^{20}$.
#[derive(Debug, Clone, Copy)]
pub enum ScalingProfile {
    /// $k\in[13,15]$, фиксированное число прогонов (типично 20).
    Debug {
        runs: usize,
    },
    /// $k\in[13,18]$ с `runs_medium`; $k\in[19,20]$ с `runs_large`.
    Prod {
        runs_medium: usize,
        runs_large: usize,
    },
}

impl ScalingProfile {
    /// Прод по умолчанию: как в исходном задании ($20$ / $6$ прогонов).
    pub fn prod_default() -> Self {
        Self::Prod {
            runs_medium: PROD_RUNS_MEDIUM_DEFAULT,
            runs_large: PROD_RUNS_LARGE_DEFAULT,
        }
    }

    /// Отладка по умолчанию: три точки, 20 прогонов.
    pub fn debug_default() -> Self {
        Self::Debug { runs: 20 }
    }
}

/// Подобрать длину сообщения (байты), дающую целевую длину трассы `target_trace`, если возможно.
pub fn find_message_len_for_trace_length(target_trace: usize) -> Option<usize> {
    if target_trace % PROGRAM_LEN != 0 {
        return None;
    }
    let blocks = target_trace / PROGRAM_LEN;
    if blocks == 0 {
        return None;
    }
    for msg_len in 0..4_000_000usize {
        if sha256_blocks_for_message_len(msg_len) == blocks {
            return Some(msg_len);
        }
    }
    None
}

/// Ведущий член по $(\log_2 n)^2$ для вклада $|H|$ (замечание после следствия~7.5): $Q|H|(\log_2 n)^2/(2\log_2\eta)$.
pub fn asymptotic_leading_h_bytes(n: usize, q: usize, digest_bytes: usize, eta: usize) -> f64 {
    if n <= 1 || eta <= 1 {
        return 0.0;
    }
    let l2 = (n as f64).log2().powi(2);
    (q * digest_bytes) as f64 * l2 / (2.0 * (eta as f64).log2())
}

/// Сдвиг + ведущий $(\log n)^2$: якорь совмещается с `expected_mean` при `anchor_n`.
pub fn asymptotic_style_total_bytes(
    n: usize,
    q: usize,
    digest_bytes: usize,
    eta: usize,
    anchor_n: usize,
    anchor_expected: usize,
) -> f64 {
    asymptotic_leading_h_bytes(n, q, digest_bytes, eta)
        + anchor_expected as f64
        - asymptotic_leading_h_bytes(anchor_n, q, digest_bytes, eta)
}

#[derive(Debug, serde::Serialize)]
pub struct ScalingRunRow {
    pub trace_length: usize,
    pub log2_trace_length: u32,
    pub run_index: usize,
    pub proof_bytes: usize,
    pub message_len: usize,
}

#[derive(Debug, serde::Serialize)]
pub struct ScalingSummaryRow {
    pub trace_length: usize,
    pub log2_trace_length: u32,
    pub num_runs: usize,
    pub message_len: usize,
    pub sha256_blocks: usize,
    pub min_bytes: usize,
    pub max_bytes: usize,
    pub mean_bytes: f64,
    pub stdev_bytes: f64,
    pub expected_mean_bytes: usize,
    pub expected_max_bytes: usize,
    pub asymptotic_style_bytes: f64,
}

pub struct ScalingConfig {
    pub proof_options: ProofOptions,
    pub out_dir: std::path::PathBuf,
}

impl Default for ScalingConfig {
    fn default() -> Self {
        Self {
            proof_options: ProofOptions::new(
                28,
                8,
                16,
                FieldExtension::None,
                8,
                31,
                BatchingMethod::Linear,
                BatchingMethod::Linear,
            ),
            out_dir: Path::new("docs/experiment_sha_winterfell/scaling_data").to_path_buf(),
        }
    }
}

fn mean_stdev(samples: &[usize]) -> (f64, f64) {
    if samples.is_empty() {
        return (0.0, 0.0);
    }
    let n = samples.len() as f64;
    let mean = samples.iter().sum::<usize>() as f64 / n;
    let var = if samples.len() < 2 {
        0.0
    } else {
        samples.iter().map(|&x| {
            let d = x as f64 - mean;
            d * d
        }).sum::<f64>()
            / (n - 1.0)
    };
    (mean, var.sqrt())
}

fn push_target_if_ok(targets: &mut Vec<(usize, usize)>, exp: u32, runs: usize) {
    let n = 1usize << exp;
    if find_message_len_for_trace_length(n).is_some() {
        targets.push((n, runs));
    } else {
        eprintln!(
            "[sha256_proof_scaling] пропуск n=2^{}: нет сообщения с нужным числом SHA-блоков (PROGRAM_LEN={})",
            exp, PROGRAM_LEN
        );
    }
}

/// Запуск измерений; см. [`ScalingProfile`].
pub fn run_scaling(
    config: ScalingConfig,
    profile: ScalingProfile,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    create_dir_all(&config.out_dir)?;

    let digest_bytes = core::mem::size_of::<<Blake3_256 as Hasher>::Digest>();
    let eta = config.proof_options.to_fri_options().folding_factor();
    let q = config.proof_options.num_queries();

    let mut targets: Vec<(usize, usize)> = Vec::new();
    match profile {
        ScalingProfile::Debug { runs } => {
            for exp in SCALING_MIN_EXP..=SCALING_MAX_EXP_DEBUG {
                push_target_if_ok(&mut targets, exp, runs);
            }
        }
        ScalingProfile::Prod {
            runs_medium,
            runs_large,
        } => {
            for exp in SCALING_MIN_EXP..=SCALING_MAX_EXP_PROD {
                let runs = if exp < SCALING_PROD_LARGE_EXP_START {
                    runs_medium
                } else {
                    runs_large
                };
                push_target_if_ok(&mut targets, exp, runs);
            }
        }
    }

    if targets.is_empty() {
        return Err("нет ни одной достижимой длины трассы".into());
    }

    let anchor_n = targets[0].0;
    let example_anchor = ExperimentShaExample::<Blake3_256>::from_input_string(
        "a".repeat(find_message_len_for_trace_length(anchor_n).unwrap_or(0)),
        config.proof_options.clone(),
        false,
    );
    let anchor_expected = example_anchor
        .expected_proof_breakdown(anchor_n)
        .map(|b| b.total())
        .unwrap_or(0);

    let mut run_rows: Vec<ScalingRunRow> = Vec::new();
    let mut summary_rows: Vec<ScalingSummaryRow> = Vec::new();

    for (target_trace, num_runs) in targets {
        let msg_len = find_message_len_for_trace_length(target_trace)
            .ok_or_else(|| format!("не найден msg_len для trace={target_trace}"))?;
        let blocks = sha256_blocks_for_message_len(msg_len);

        let example_stats = ExperimentShaExample::<Blake3_256>::from_input_string(
            "a".repeat(msg_len),
            config.proof_options.clone(),
            false,
        );
        let expected_mean = example_stats
            .expected_proof_breakdown(target_trace)
            .map(|b| b.total())
            .unwrap_or(0);
        let expected_max = example_stats.worst_case_proof_breakdown(target_trace).total();
        let asym = asymptotic_style_total_bytes(
            target_trace,
            q,
            digest_bytes,
            eta,
            anchor_n,
            anchor_expected,
        );

        let mut samples: Vec<usize> = Vec::with_capacity(num_runs);
        for run_index in 0..num_runs {
            let input_str = super::random_ascii_string(msg_len);
            let example = ExperimentShaExample::<Blake3_256>::from_input_string(
                input_str,
                config.proof_options.clone(),
                false,
            );
            let bytes = example.prove_without_parameters_print().to_bytes().len();
            samples.push(bytes);
            run_rows.push(ScalingRunRow {
                trace_length: target_trace,
                log2_trace_length: target_trace.ilog2(),
                run_index,
                proof_bytes: bytes,
                message_len: msg_len,
            });
            eprintln!(
                "trace_len={} run {}/{} → {} B",
                target_trace,
                run_index + 1,
                num_runs,
                bytes
            );
        }

        let (mean, stdev) = mean_stdev(&samples);
        summary_rows.push(ScalingSummaryRow {
            trace_length: target_trace,
            log2_trace_length: target_trace.ilog2(),
            num_runs,
            message_len: msg_len,
            sha256_blocks: blocks,
            min_bytes: *samples.iter().min().unwrap_or(&0),
            max_bytes: *samples.iter().max().unwrap_or(&0),
            mean_bytes: mean,
            stdev_bytes: stdev,
            expected_mean_bytes: expected_mean,
            expected_max_bytes: expected_max,
            asymptotic_style_bytes: asym,
        });
    }

    let runs_path = config.out_dir.join("sha256_scaling_runs.csv");
    let mut wtr = csv::Writer::from_path(&runs_path)?;
    for row in &run_rows {
        wtr.serialize(row)?;
    }
    wtr.flush()?;

    let summary_path = config.out_dir.join("sha256_scaling_summary.csv");
    let mut wtr = csv::Writer::from_path(&summary_path)?;
    for row in &summary_rows {
        wtr.serialize(row)?;
    }
    wtr.flush()?;

    write_scaling_plot(&summary_rows, &config.out_dir.join("sha256_scaling_proof_size.png"))?;

    let mut meta = File::create(config.out_dir.join("README.txt"))?;
    let profile_line = match profile {
        ScalingProfile::Debug { runs } => {
            format!(
                "profile=DEBUG k={}..={} runs={}",
                SCALING_MIN_EXP, SCALING_MAX_EXP_DEBUG, runs
            )
        }
        ScalingProfile::Prod {
            runs_medium,
            runs_large,
        } => {
            format!(
                "profile=PROD k={}..={} runs={}, k={}..={} runs={}",
                SCALING_MIN_EXP,
                SCALING_PROD_LARGE_EXP_START - 1,
                runs_medium,
                SCALING_PROD_LARGE_EXP_START,
                SCALING_MAX_EXP_PROD,
                runs_large
            )
        }
    };
    writeln!(
        meta,
        "PROGRAM_LEN={}\nTABLE_WIDTH={}\nProofOptions: Q={}, blowup={}, folding={}, grinding={}\nanchor_n={} expected_anchor={}\n{}\n",
        PROGRAM_LEN,
        TABLE_WIDTH,
        q,
        config.proof_options.blowup_factor(),
        eta,
        config.proof_options.grinding_factor(),
        anchor_n,
        anchor_expected,
        profile_line
    )?;

    println!(
        "CSV: {}\nCSV: {}\nPNG: {}",
        runs_path.display(),
        summary_path.display(),
        config.out_dir.join("sha256_scaling_proof_size.png").display()
    );

    Ok(())
}

fn write_scaling_plot(
    rows: &[ScalingSummaryRow],
    png_path: &Path,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if rows.is_empty() {
        return Ok(());
    }
    if let Some(p) = png_path.parent() {
        create_dir_all(p)?;
    }

    let x: Vec<f64> = rows.iter().map(|r| r.log2_trace_length as f64).collect();
    let y_mean: Vec<f64> = rows.iter().map(|r| r.mean_bytes).collect();
    let y_exp: Vec<f64> = rows.iter().map(|r| r.expected_mean_bytes as f64).collect();
    let y_theory_max: Vec<f64> = rows.iter().map(|r| r.expected_max_bytes as f64).collect();
    let y_asym: Vec<f64> = rows.iter().map(|r| r.asymptotic_style_bytes).collect();

    let x_min = x.iter().cloned().fold(f64::INFINITY, f64::min);
    let x_max = x.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
    let y_min = y_mean
        .iter()
        .chain(y_exp.iter())
        .chain(y_theory_max.iter())
        .chain(y_asym.iter())
        .cloned()
        .fold(f64::INFINITY, f64::min);
    let y_max = y_mean
        .iter()
        .chain(y_exp.iter())
        .chain(y_theory_max.iter())
        .chain(y_asym.iter())
        .cloned()
        .fold(f64::NEG_INFINITY, f64::max);
    let xm = (x_max - x_min).max(0.5) * 0.05;
    let ym = (y_max - y_min).max(100.0) * 0.05;

    let root = BitMapBackend::new(png_path, (900, 560)).into_drawing_area();
    root.fill(&WHITE)?;

    let mut chart = ChartBuilder::on(&root)
        .caption(
            "experiment_sha (SHA-256 AIR): размер proof vs log2(n)",
            ("sans-serif", 22),
        )
        .margin(10)
        .x_label_area_size(44)
        .y_label_area_size(52)
        .build_cartesian_2d(
            (x_min - xm)..(x_max + xm),
            (y_min - ym)..(y_max + ym),
        )?;

    chart
        .configure_mesh()
        .x_desc("log2(n), n — длина трассы")
        .y_desc("байты")
        .draw()?;

    chart
        .draw_series(LineSeries::new(
            x.iter().zip(y_mean.iter()).map(|(&a, &b)| (a, b)),
            &BLUE,
        ))?
        .label("среднее (измерения)")
        .legend(|(x, y)| PathElement::new(vec![(x, y), (x + 12, y)], &BLUE));

    chart
        .draw_series(LineSeries::new(
            x.iter().zip(y_exp.iter()).map(|(&a, &b)| (a, b)),
            &GREEN,
        ))?
        .label("ожидаемое среднее (E_nodes)")
        .legend(|(x, y)| PathElement::new(vec![(x, y), (x + 12, y)], &GREEN));

    chart
        .draw_series(LineSeries::new(
            x.iter().zip(y_theory_max.iter()).map(|(&a, &b)| (a, b)),
            &RED,
        ))?
        .label("верхняя оценка (т. 7.1(i))")
        .legend(|(x, y)| PathElement::new(vec![(x, y), (x + 12, y)], &RED));

    chart
        .draw_series(LineSeries::new(
            x.iter().zip(y_asym.iter()).map(|(&a, &b)| (a, b)),
            &MAGENTA,
        ))?
        .label("асимптотика (ведущий Q|H|(log n)^2)")
        .legend(|(x, y)| PathElement::new(vec![(x, y), (x + 12, y)], &MAGENTA));

    chart.configure_series_labels().border_style(&BLACK).draw()?;
    root.present()?;
    Ok(())
}
