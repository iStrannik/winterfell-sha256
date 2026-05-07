// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

//! CSV export and histogram plots for FRI batch Merkle `digest` counts per layer.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use csv::Writer;
use fri::{folding::fold_positions, FriOptions};
use plotters::prelude::*;
use serde::Serialize;

/// One row per (run, FRI layer) for spreadsheet / plotting tools.
#[derive(Clone, Debug, Serialize)]
pub struct FriDigestStatsRow {
    pub run: usize,
    pub layer: usize,
    pub digest_cells_actual: usize,
    pub digest_cells_expected: usize,
    pub opened_leaves: usize,
    pub tree_leaf_capacity: usize,
    pub merkle_depth: u8,
    pub merkle_leaves_formula: usize,
    pub qi_expected: usize,
}

/// Shared buffer for [`super::prover::ExperimentShaProver`] during a stats run.
#[derive(Clone)]
pub struct FriDigestRunRecorder {
    pub rows: Arc<Mutex<Vec<FriDigestStatsRow>>>,
    pub run: usize,
}

impl FriDigestRunRecorder {
    pub fn new(run: usize) -> Self {
        Self {
            rows: Arc::new(Mutex::new(Vec::new())),
            run,
        }
    }

    pub fn with_shared_rows(run: usize, rows: Arc<Mutex<Vec<FriDigestStatsRow>>>) -> Self {
        Self { rows, run }
    }
}

/// Expected number of Merkle batch digest cells under **uniform i.i.d. leaves** (только то, что
/// попадает в `BatchMerkleProof.nodes` — **без** хэшей открытых листьев, они в `values`):
///
/// Σ_{d=1}^{h−2} 2^d · (1 − (1 − 2^{−d})^Q), где `h = ⌊log₂(leaves)⌋` (= `merkle_depth`).
///
/// Уровень **d = h − 1** не суммируем: там co-path граничит с листьями; учёт «как 2^{h−1} листьев»
/// завышает ожидание относительно фактического числа digest-слотов в `nodes`.
///
/// Для самого маленького дерева (`h == 2`) остаётся один член `d = 1`.
pub fn expected_merkle_batch_digest_uniform(h: usize, q: usize) -> usize {
    if h <= 1 || q == 0 {
        return 0;
    }
    let mut sum = 0.0f64;
    let qi = q as i32;
    // d = h−1 исключаем; при h==2 суммируем только d=1.
    let end = if h > 2 { h - 1 } else { h };
    for d in 1..end {
        let pow2d = 2_f64.powi(d as i32);
        let p = 1.0 / pow2d;
        sum += pow2d * (1.0 - (1.0 - p).powi(qi));
    }
    (sum.round().max(0.0).min(usize::MAX as f64)) as usize
}

/// Per-layer `(merkle_leaves, Q_i, expected_digest_cells)` matching `fold_positions` in FRI query phase.
///
/// **Важно:** начальный `query_positions` должен быть набором **различных** индексов на LDE; не используйте
/// шаг `i·N_LDE/Q` — при типичном `η` такие остатки по домену схлопываются при `%` в `fold_positions`,
/// и `Q_i` занижается (формула путей станет сильно ниже факта для реальных позиций из монеты).
pub fn expected_fri_digest_per_layer(
    lde_domain_size: usize,
    query_positions: &[usize],
    fri_options: &FriOptions,
) -> Vec<(usize, usize, usize)> {
    let ff = fri_options.folding_factor();
    let nl = fri_options.num_fri_layers(lde_domain_size);
    let mut pos = query_positions.to_vec();
    let mut domain_size = lde_domain_size;
    let mut out = Vec::with_capacity(nl);
    for _ in 0..nl {
        pos = fold_positions(&pos, domain_size, ff);
        let merkle_leaves = domain_size / ff;
        let h = merkle_leaves.ilog2() as usize;
        domain_size /= ff;
        let qi = pos.len();
        let exp_digest = expected_merkle_batch_digest_uniform(h, qi);
        out.push((merkle_leaves, qi, exp_digest));
    }
    out
}

pub fn write_csv(path: &str, rows: &[FriDigestStatsRow]) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if let Some(parent) = std::path::Path::new(path).parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut wtr = Writer::from_path(path)?;
    for row in rows {
        wtr.serialize(row)?;
    }
    wtr.flush()?;
    println!("CSV сохранён: {}", path);
    Ok(())
}

/// For each FRI layer, a histogram of `digest_cells_actual` over runs (`{plot_prefix}_layer{i}_digest_actual.png`).
pub fn plot_digest_layer_histograms(
    rows: &[FriDigestStatsRow],
    plot_prefix: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let max_layer = rows.iter().map(|r| r.layer).max().unwrap_or(0);
    for layer in 0..=max_layer {
        let vals: Vec<usize> = rows
            .iter()
            .filter(|r| r.layer == layer)
            .map(|r| r.digest_cells_actual)
            .collect();
        if vals.len() < 2 {
            continue;
        }
        let path = format!("{plot_prefix}_layer{layer}_digest_actual.png");
        plot_single_histogram(
            &path,
            &format!("FRI layer {layer}: digest_cells (факт), N={}", vals.len()),
            &vals,
        )?;
    }
    Ok(())
}

fn plot_single_histogram(
    path: &str,
    caption: &str,
    vals: &[usize],
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let min_v = *vals.iter().min().unwrap();
    let max_v = *vals.iter().max().unwrap();
    let bins = (vals.len() / 3).clamp(5, 24);
    let span = (max_v - min_v + 1).max(1);
    let bin_w = (span + bins - 1) / bins;
    let mut counts = vec![0usize; bins];
    for v in vals {
        let idx = ((*v).saturating_sub(min_v) / bin_w).min(bins - 1);
        counts[idx] += 1;
    }
    let max_c = counts.iter().copied().max().unwrap_or(1);

    if let Some(parent) = std::path::Path::new(path).parent() {
        std::fs::create_dir_all(parent)?;
    }

    let root = BitMapBackend::new(path, (760, 440)).into_drawing_area();
    root.fill(&WHITE)?;
    let mut chart = ChartBuilder::on(&root)
        .caption(caption, ("sans-serif", 16))
        .margin(15)
        .x_label_area_size(40)
        .y_label_area_size(45)
        .build_cartesian_2d(0..bins, 0..max_c.saturating_add(1))?;

    chart
        .configure_mesh()
        .x_desc(format!("bin (width≈{bin_w}, range {min_v}…{max_v})"))
        .y_desc("count")
        .draw()?;

    chart.draw_series((0..bins).filter(|&i| counts[i] > 0).map(|i| {
        Rectangle::new(
            [(i, 0), (i + 1, counts[i])],
            RGBColor(50, 100, 200).filled(),
        )
    }))?;

    root.present()?;
    println!("График: {}", path);
    Ok(())
}

/// Summary table: mean / min / max of actual digests per layer (printed after CSV).
pub fn print_digest_summary(rows: &[FriDigestStatsRow]) {
    let mut by_layer: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    for r in rows {
        by_layer.entry(r.layer).or_default().push(r.digest_cells_actual);
    }
    println!("\n=== Сводка digest_cells (факт) по слоям ===");
    println!("{:<6} {:>8} {:>8} {:>8} {:>8}", "слой", "N", "mean", "min", "max");
    for (layer, v) in by_layer {
        let n = v.len();
        let sum: usize = v.iter().sum();
        let mean = sum as f64 / n as f64;
        let min = *v.iter().min().unwrap();
        let max = *v.iter().max().unwrap();
        println!(
            "{:<6} {:>8} {:>8.2} {:>8} {:>8}",
            layer, n, mean, min, max
        );
    }
    println!();
}
