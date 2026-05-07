// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use core::{marker::PhantomData, mem::size_of};

use core_utils::Serializable;
use tracing::{field, info_span};
use winterfell::{
    crypto::{DefaultRandomCoin, ElementHasher, MerkleTree},
    math::{fields::f128::BaseElement, FieldElement},
    FieldExtension, Proof, ProofOptions, Prover, Trace, VerifierError,
};

use crate::experiment_sha::vm_program::PROGRAM_LEN;
use crate::proof_decomposition::{ExpectedProofBreakdown, ProofDecomposition};
use crate::{experiment_sha::{air::PublicInputs, table_constants::TABLE_WIDTH, utis::{bytes_to_elements, prepare_sha_256_block, prepare_sha_256_block_silent}}, Blake3_192, Blake3_256, Example, ExampleOptions, HashFunction, Sha3_256};

mod air;
mod assertions;
use air::ExperimentShaAir;
pub mod table_constants;
mod transitions_constants;
mod transitions;
mod utis;
mod table;
mod vm_program;
mod prover;
pub mod fri_digest_stats;
#[cfg(feature = "std")]
pub mod proof_scaling;
use prover::ExperimentShaProver;

pub fn custom_sha256(message: &[u8]) -> [u8; 32] {
    /* Предполагаемый вид таблицы:
    Первые колонки в строке - хешируемый блок данных(64 байта)
    За ним - хеш предыдущего шага хеширование (32 байта) Итого - 96 байт.
    Если использовать поле f128 - в элемент можно засунуть <= 15 байт без риска переполнения, 
    то есть в целом можно хранить по одному байту.
    - есть начальное значение iv
    - в блоке байты делятся на слова по 4(u32) - они формируют первые 16 слов в массиве w
    - остальные слова в w формируются на основе предыдущих вычислений w(нужно 4 значения - w[i - 15], w[i - 2], w[i - 16], w[i - 7])
    - всего происходит 64 итераций хеширования блока:
        - на каждой итерации преобразуется массив state из 8 u32 - суммарно 32 байта (256 бит) - на первой итерации это iv
        - для вычисления новых значений массива нужны только они и одно слово из w
    - после итераций к изначальному iv прибавляется state

    Таким образом для вычисления хеша необходимо протаскивать между строками хотя бы 32 байта(iv) + w(4 байта прикопать через assert либо полноценные 64 байта) + 32 байта(state)
    Итого: 128 байт * 8 = 1024 бита. Это 1024 колонок, если хранить по биту, либо 64 колонки, если хранить по 16 бит в одной колонке. 
    Два пути как с этим жить:
    - если использовать уже реализованные поля
        - по одному биту в элементе - это 65 * 8 = 520 столбцов - очень много и нерационально. Но все операции проводить очень легко
        - плотненько уложить по 15 байт в число, тогда понадобится всего 5 столбцов (или ещё проще просто по байту в столбец, тогда будет )


    Как можно упростить пруфинг:
    - на этапе преобразования строки сделать предподсчёт w и отправить их публичными данными(условнно добавить в колонку с инпутом, добавить на них assert).
    Как хешируется один блок:
    - 

    Функции, которые используются при хешировании:
    - &
    - сложение по модулю 2^32, 
    - циклический побитовый сдвиг вправо
    - побитовый сдвиг вправо
    - xor
    - ~
    -
    
     */

    // iv(начальное значение для блока) - 32 байта
    // размер хешируемого блока - 64 байта

    // окончательное формирование блоков - добавить байт 0x80, последние 8 байт заполнить длинной сообщение в битах
    let mut m = message.to_vec();
    m.push(0x80);
    if 64 - m.len() % 64 < 8 {
        m.append(&mut vec![0u8; 64 - m.len() % 64])
    }
    m.append(&mut vec![0u8; 64 - m.len() % 64 - 8]);
    m.append(&mut (message.len() as u64 * 8).to_be_bytes().to_vec());
    let blocks = m.chunks_exact(64);
    println!("blocks = {:?}", blocks.len());

    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ];

    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ];

    // Итерация по блокам данных
    for block in blocks {
        // Объединение байтов u8 в набор u32
        let mut w: Vec<u32> = block.chunks_exact(4).map(|chunk| {
            u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]])
        }).collect();
        w.append(&mut vec![0u32; 48]);

        // Заполнение оставшихся 48 слов
        for i in 16..64 {
            let s0 = (w[i - 15].rotate_right(7)) ^ (w[i - 15].rotate_right(18)) ^ (w[i - 15] >> 3);
            let s1 = (w[i - 2].rotate_right(17)) ^ (w[i - 2].rotate_right(19)) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
        }

        // println!("initial w");
        // println!("{:?}", w.iter().map(|x| format!("{:x}", x)).collect::<Vec<String>>().join(" "));

        // println!("inishial h");
        // println!("{:?}", h.iter().map(|x| format!("{:x}", x)).collect::<Vec<String>>().join(" "));

        // a, b, c, d, e, f, g, h
        // 0, 1, 2, 3, 4, 5, 6, 7
        let mut tmp_h: [u32; 8] = h.clone();

        // 64 раунда хэширования
        for i in 0..64 {
            let s1 = (tmp_h[4].rotate_right(6)) ^ (tmp_h[4].rotate_right(11)) ^ (tmp_h[4].rotate_right(25));
            let ch = (tmp_h[4] & tmp_h[5]) ^ (!tmp_h[4] & tmp_h[6]);
            let temp1 = tmp_h[7].wrapping_add(s1).wrapping_add(ch).wrapping_add(K[i]).wrapping_add(w[i]);
            let s0 = (tmp_h[0].rotate_right(2)) ^ (tmp_h[0].rotate_right(13)) ^ (tmp_h[0].rotate_right(22));
            let maj = (tmp_h[0] & tmp_h[1]) ^ (tmp_h[0] & tmp_h[2]) ^ (tmp_h[1] & tmp_h[2]);
            let temp2 = s0.wrapping_add(maj);

            tmp_h[7] = tmp_h[6];
            tmp_h[6] = tmp_h[5];
            tmp_h[5] = tmp_h[4];
            tmp_h[4] = tmp_h[3].wrapping_add(temp1);
            tmp_h[3] = tmp_h[2];
            tmp_h[2] = tmp_h[1];
            tmp_h[1] = tmp_h[0];
            tmp_h[0] = temp1.wrapping_add(temp2);
        }

        for i in 0..8 {
            h[i] = h[i].wrapping_add(tmp_h[i]);
        }
    }

    h.map(|chunk| chunk.to_be_bytes()).concat().as_slice().try_into().unwrap()
}


// EXPERIMENT SHA EXAMPLE
// ================================================================================================

/// Cyclically proves SHA example with varying ASCII inputs, records FRI batch digest counts per layer to CSV, then plots histograms.
#[cfg(feature = "std")]
pub fn run_fri_digest_stats_cycle(
    options: &ExampleOptions,
    string_length: usize,
    cycles: usize,
    csv_path: &str,
    plot_prefix: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use std::sync::{Arc, Mutex};

    use fri_digest_stats::FriDigestStatsRow;

    let (base_options, hash_fn) = options.to_proof_options(28, 8);
    let rows: Arc<Mutex<Vec<FriDigestStatsRow>>> = Arc::new(Mutex::new(Vec::new()));

    match hash_fn {
        HashFunction::Blake3_192 => {
            run_digest_stats_inner::<Blake3_192>(base_options, string_length, cycles, csv_path, plot_prefix, rows)
        },
        HashFunction::Blake3_256 => {
            run_digest_stats_inner::<Blake3_256>(base_options, string_length, cycles, csv_path, plot_prefix, rows)
        },
        HashFunction::Sha3_256 => {
            run_digest_stats_inner::<Sha3_256>(base_options, string_length, cycles, csv_path, plot_prefix, rows)
        },
        _ => Err("experiment-sha FRI stats: supported hash_fn are blake3_192, blake3_256, sha3_256".into()),
    }
}

/// Printable ASCII (UTF-8), length `length`; uses OS RNG via `winter-rand-utils`.
#[cfg(feature = "std")]
pub(crate) fn random_ascii_string(length: usize) -> String {
    if length == 0 {
        return String::new();
    }
    use rand_utils::rand_vector;
    rand_vector::<u8>(length)
        .into_iter()
        .map(|b| char::from_u32(u32::from(b % 95) + 32).unwrap_or('a'))
        .collect()
}

#[cfg(feature = "std")]
fn run_digest_stats_inner<H: ElementHasher>(
    options: ProofOptions,
    string_length: usize,
    cycles: usize,
    csv_path: &str,
    plot_prefix: &str,
    shared_rows: std::sync::Arc<std::sync::Mutex<Vec<fri_digest_stats::FriDigestStatsRow>>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    H: ElementHasher<BaseField = BaseElement> + Sync,
    H::Digest: Default,
{
    use fri_digest_stats::FriDigestRunRecorder;
    use winterfell::Prover;

    for run in 0..cycles {
        println!("fri digest stats: итерация {}/{}", run + 1, cycles);
        let s = random_ascii_string(string_length);
        let example = ExperimentShaExample::<H>::from_input_string(s, options.clone(), false);
        let recorder = FriDigestRunRecorder::with_shared_rows(run, shared_rows.clone());
        let prover =
            ExperimentShaProver::<H>::new_with_fri_digest_recorder(options.clone(), recorder, true);
        let trace = prover.build_trace(PublicInputs {
            data: example.input_data.clone(),
            result: example.result.clone(),
        });
        prover
            .prove(trace)
            .map_err(|e| format!("prove run {run}: {e:?}"))?;
    }
    let data = shared_rows
        .lock()
        .map_err(|e| format!("stats mutex: {e}"))?
        .clone();
    fri_digest_stats::write_csv(csv_path, &data)?;
    fri_digest_stats::print_digest_summary(&data);
    fri_digest_stats::plot_digest_layer_histograms(&data, plot_prefix)?;
    Ok(())
}

pub fn get_example(
    options: &ExampleOptions,
    string_length: usize,
) -> Result<Box<dyn Example>, String> {
    let (options, hash_fn) = options.to_proof_options(28, 8);

    match hash_fn {
        HashFunction::Blake3_192 => {
            Ok(Box::new(ExperimentShaExample::<Blake3_192>::new(string_length, options)))
        },
        HashFunction::Blake3_256 => {
            Ok(Box::new(ExperimentShaExample::<Blake3_256>::new(string_length, options)))
        },
        HashFunction::Sha3_256 => {
            Ok(Box::new(ExperimentShaExample::<Sha3_256>::new(string_length, options)))
        },
        _ => Err("The specified hash function cannot be used with this example.".to_string()),
    }
}

pub struct ExperimentShaExample<H: ElementHasher> {
    options: ProofOptions,
    input_data: Vec<[BaseElement; 16]>,
    result: Vec<BaseElement>,
    _hasher: PhantomData<H>,
}

/// FRI layer `i` commits to `n_lde / ff^(i+1)` листьев-хэшей (`fri/src/prover` + `build_layer_commitment`).

/// Число коэффициентов remainder после `L` свёрток: `|domain|/blowup` на последнем слое (`set_remainder`).
fn fri_remainder_num_coeffs(n_lde: usize, ff: usize, num_layers: usize, blowup: usize) -> usize {
    let mut domain = n_lde;
    for _ in 0..num_layers {
        domain /= ff;
    }
    domain / blowup
}

/// Диагностика FRI: на каждом слое число **листьев Merkle-дерева** (размер домена коммита) и **Q_i**
/// — число запросов в batch после `fold_positions` (из длины `values` в proof; может быть < Q).
fn print_fri_layers_merkle_and_query_stats(
    proof: &Proof,
    decomposition: &ProofDecomposition,
    ff: usize,
    b_e: usize,
) {
    let n_lde = proof.lde_domain_size();
    let q_top = proof.num_unique_queries as usize;
    let cell = ff.saturating_mul(b_e);

    println!("\n=== experiment_sha (после prove): FRI — Merkle-листья и Q_i по сериализованному proof ===");
    println!(
        "Q (уникальных позиций на LDE после выборки): {}\n\
         Листья Merkle на слое i: N_LDE / η^(i+1) — полный домен дерева.\n\
         Q_i: из размера values слоя / (η·B_E); уменьшение Q_i — из-за fold_positions.\n\
         Фактические Merkle-статистики по слоям см. блок «во время prove: FRI Merkle — факт» выше.\n",
        q_top
    );
    println!(
        "{:<6} {:>14} {:>10} {:>8} {:>14} {:>12}",
        "слой",
        "Merkle листьев",
        "⌊log2⌋",
        "Q_i",
        "values байт",
        "paths байт"
    );
    println!("{}", "-".repeat(70));

    let mut merkle_leaves = n_lde;
    let mut min_q_i = q_top;
    for layer in &decomposition.fri_decomposition.layer_sizes {
        merkle_leaves /= ff;
        let log2_leaves = merkle_leaves.ilog2() as usize;
        let q_i = if cell > 0 && layer.values_size % cell == 0 {
            layer.values_size / cell
        } else {
            0
        };
        min_q_i = min_q_i.min(q_i);
        println!(
            "{:<6} {:>14} {:>10} {:>8} {:>14} {:>12}",
            layer.layer_index,
            merkle_leaves,
            log2_leaves,
            q_i,
            layer.values_size,
            layer.paths_size
        );
    }
    println!("{}", "-".repeat(70));
    if min_q_i < q_top {
        println!(
            "Замечание: на одном из слоёв Q_i < Q — batch Merkle и values меньше, чем при «полных» Q запросах на каждом слое."
        );
    }
    println!();
}

impl<H: ElementHasher> ExperimentShaExample<H>
where
    H: ElementHasher<BaseField = BaseElement> + Sync,
    H::Digest: Default,
{
    /// Expected proof size (bytes) from formulas in proof_size.md (no AIR/context calls).
    /// Uses compact form: single-segment trace, 1-byte usize for length prefixes, **batch** Merkle path sizes.
    ///
    /// Merkle digest count (model): **E(h,Q) = Σ_{d=1}^{h-2} 2^d (1 − (1 − 2^{-d})^Q)** (уровень d=h−1 у листьев не входит — листья не в `nodes`); bytes ≈ E×D.
    /// Для FRI по слоям — тот же E(h_i, Q_i) после `fold_positions`. Симуляция позиций: **0..Q−1** на LDE
    /// (не `i·N_LDE/Q`: такой шаг резонирует с `η` и даёт искусственное слияние остатков при `%`, занижая Q_i и пути).
    ///
    /// Formulas used:
    /// - N_LDE = N × blowup, depth_LDE = ⌈log₂(N_LDE)⌉
    /// - D_max = max over constraints of (base·(N−1) + Σ (N/c)·(c−1)); for SHA AIR max is (2, [PROGRAM_LEN])
    /// - C_cols = max(1, ⌈(D_max − (N−k)) / N⌉), k = 1
    /// - L: same as Winterfell FriOptions::num_fri_layers(N_LDE) (while domain_size > max_remainder_size: domain_size /= ff, L += 1)
    /// - Trace/constraint paths: E(depth_LDE, Q)×D (LDE Merkle).
    /// - FRI paths: сумма по слоям E(h_i, Q_i)×D; remainder: `(N_LDE/ff^L)/blowup` коэффициентов × B_E.
    fn compute_expected_breakdown(&self, trace_length: usize) -> ExpectedProofBreakdown {
        let n = trace_length;
        let w = TABLE_WIDTH;
        let q = self.options.num_queries();
        let blowup = self.options.blowup_factor();
        let fri = self.options.to_fri_options();
        let ff = fri.folding_factor();
        let r = fri.remainder_max_degree() + 1;
        let b = size_of::<BaseElement>();
        let d = size_of::<H::Digest>();
        let ext_degree = match self.options.field_extension() {
            FieldExtension::None => 1,
            FieldExtension::Quadratic => 2,
            FieldExtension::Cubic => 3,
        };
        let b_e = b * ext_degree;

        let n_lde = n * blowup;
        let depth_lde = n_lde.ilog2() as usize;

        let d_max = 2 * (n - 1) + (n / PROGRAM_LEN) * (PROGRAM_LEN - 1);
        let c_cols = core::cmp::max(1, (d_max - (n - 1)).div_ceil(n));

        // Match Winterfell FriOptions::num_fri_layers(domain_size) exactly.
        let max_remainder_size = r * blowup;
        let mut domain_size = n_lde;
        let mut l = 0;
        while domain_size > max_remainder_size {
            domain_size /= ff;
            l += 1;
        }

        let trace_digest_cells = fri_digest_stats::expected_merkle_batch_digest_uniform(depth_lde, q);
        let trace_merkle_bytes = trace_digest_cells.saturating_mul(d);

        let fri_query_positions_sim: Vec<usize> = (0..q.max(1)).collect();
        let fri_digest_cells_sum: usize = fri_digest_stats::expected_fri_digest_per_layer(n_lde, &fri_query_positions_sim, &fri)
            .iter()
            .map(|(_, _, cells)| *cells)
            .sum();
        let fri_paths_sum = fri_digest_cells_sum.saturating_mul(d);
        let remainder_coeffs = fri_remainder_num_coeffs(n_lde, ff, l, blowup);
        let remainder_bytes = remainder_coeffs * b_e;

        const C_CTX_ESTIMATE: usize = 128;

        ExpectedProofBreakdown {
            context: C_CTX_ESTIMATE,
            num_unique_queries: 1,
            commitments: 4 + (l + 3) * d,
            trace_queries: 3 + q * w * b + trace_merkle_bytes,
            constraint_queries: 2 + q * c_cols * b_e + trace_merkle_bytes,
            ood_frame: 6 + 2 * (w + c_cols) * b_e,
            fri_proof: 4 + l * (8 + q * ff * b_e) + remainder_bytes + fri_paths_sum,
            pow_nonce: 8,
        }
    }

    /// Верхняя оценка размера Merkle batch по теореме~7.1\textup{(i)}: $N_{\mathrm{auth}}\le Q(h-\lfloor\log_2 Q\rfloor)$ digest-узлов;
    /// применяется к trace/constraint LDE и как грубый worst-case по слоям FRI ($Q h_i$ на слой).
    fn compute_worst_case_breakdown(&self, trace_length: usize) -> ExpectedProofBreakdown {
        let n = trace_length;
        let w = TABLE_WIDTH;
        let q = self.options.num_queries();
        let blowup = self.options.blowup_factor();
        let fri = self.options.to_fri_options();
        let ff = fri.folding_factor();
        let r = fri.remainder_max_degree() + 1;
        let b = size_of::<BaseElement>();
        let d = size_of::<H::Digest>();
        let ext_degree = match self.options.field_extension() {
            FieldExtension::None => 1,
            FieldExtension::Quadratic => 2,
            FieldExtension::Cubic => 3,
        };
        let b_e = b * ext_degree;

        let n_lde = n * blowup;
        let depth_lde = n_lde.ilog2() as usize;

        let d_max = 2 * (n - 1) + (n / PROGRAM_LEN) * (PROGRAM_LEN - 1);
        let c_cols = core::cmp::max(1, (d_max - (n - 1)).div_ceil(n));

        let max_remainder_size = r * blowup;
        let mut domain_size = n_lde;
        let mut l = 0;
        while domain_size > max_remainder_size {
            domain_size /= ff;
            l += 1;
        }

        let fq = if q <= 1 { 0usize } else { q.ilog2() as usize };
        let trace_merkle_worst = q
            .saturating_mul(depth_lde.saturating_sub(fq))
            .saturating_mul(d)
            .saturating_add(2 + q);

        let mut fri_paths_worst = 0usize;
        let mut dom = n_lde;
        for _ in 0..l {
            dom /= ff;
            let h_layer = dom.ilog2() as usize;
            fri_paths_worst =
                fri_paths_worst.saturating_add(q.saturating_mul(h_layer).saturating_mul(d));
        }
        let remainder_coeffs = fri_remainder_num_coeffs(n_lde, ff, l, blowup);
        let remainder_bytes = remainder_coeffs * b_e;

        const C_CTX_ESTIMATE: usize = 128;

        ExpectedProofBreakdown {
            context: C_CTX_ESTIMATE,
            num_unique_queries: 1,
            commitments: 4 + (l + 3) * d,
            trace_queries: 3 + q * w * b + trace_merkle_worst,
            constraint_queries: 2 + q * c_cols * b_e + trace_merkle_worst,
            ood_frame: 6 + 2 * (w + c_cols) * b_e,
            fri_proof: 4 + l * (8 + q * ff * b_e) + remainder_bytes + fri_paths_worst,
            pow_nonce: 8,
        }
    }

    /// Как `compute_expected_breakdown`, но подставляет фактические context, L и Q из proof.
    /// Размеры batch Merkle (trace, constraint, FRI paths) — та же модель **E(h,Q)**; для FRI —
    /// те же симулированные позиции, что в `compute_expected_breakdown` (см. комментарий там).
    fn compute_expected_breakdown_with_actuals(
        &self,
        trace_length: usize,
        actual_context_size: usize,
        actual_fri_layers: usize,
        actual_num_unique_queries: usize,
    ) -> ExpectedProofBreakdown {
        let n = trace_length;
        let w = TABLE_WIDTH;
        let q = actual_num_unique_queries.max(1); // use actual from proof
        let blowup = self.options.blowup_factor();
        let fri = self.options.to_fri_options();
        let ff = fri.folding_factor();
        let b = size_of::<BaseElement>();
        let d = size_of::<H::Digest>();
        let ext_degree = match self.options.field_extension() {
            FieldExtension::None => 1,
            FieldExtension::Quadratic => 2,
            FieldExtension::Cubic => 3,
        };
        let b_e = b * ext_degree;

        let n_lde = n * blowup;
        let depth_lde = n_lde.ilog2() as usize;

        let d_max = 2 * (n - 1) + (n / PROGRAM_LEN) * (PROGRAM_LEN - 1);
        let c_cols = core::cmp::max(1, (d_max - (n - 1)).div_ceil(n));

        let l = actual_fri_layers;

        let trace_digest_cells = fri_digest_stats::expected_merkle_batch_digest_uniform(depth_lde, q);
        let trace_merkle_bytes = trace_digest_cells.saturating_mul(d);

        let fri_query_positions_sim: Vec<usize> = (0..q.max(1)).collect();
        let fri_digest_cells_sum: usize = fri_digest_stats::expected_fri_digest_per_layer(n_lde, &fri_query_positions_sim, &fri)
            .into_iter()
            .take(l)
            .map(|(_, _, cells)| cells)
            .sum();
        let fri_paths_sum = fri_digest_cells_sum.saturating_mul(d);

        let remainder_coeffs = fri_remainder_num_coeffs(n_lde, ff, l, blowup);
        let remainder_bytes = remainder_coeffs * b_e;

        // Queries outer: 1×usize (trace_queries list len) + per segment: 2×usize (values len, proof len)
        let trace_overhead = 1 + 2; // list len + one Queries: two length prefixes
        let constraint_overhead = 2; // one Queries: two length prefixes

        ExpectedProofBreakdown {
            context: actual_context_size,
            num_unique_queries: 1,
            commitments: 4 + (l + 3) * d,
            trace_queries: trace_overhead + q * w * b + trace_merkle_bytes,
            constraint_queries: constraint_overhead + q * c_cols * b_e + trace_merkle_bytes,
            ood_frame: 6 + 2 * (w + c_cols) * b_e,
            fri_proof: 4 + l * (8 + q * ff * b_e) + remainder_bytes + fri_paths_sum,
            pow_nonce: 8,
        }
    }

    fn expected_proof_size_bytes(&self, trace_length: usize) -> usize {
        self.compute_expected_breakdown(trace_length).total()
    }

    /// Worst-case Merkle верхняя оценка (теорема~7.1\textup{(i)}), см. `compute_worst_case_breakdown`.
    pub fn worst_case_proof_breakdown(&self, trace_length: usize) -> ExpectedProofBreakdown {
        self.compute_worst_case_breakdown(trace_length)
    }

    /// Как `Example::prove`, но без `print_input_parameters` (для пакетных прогонов).
    pub fn prove_without_parameters_print(&self) -> Proof {
        let prover = ExperimentShaProver::<H>::new(self.options.clone());
        let trace = prover.build_trace(PublicInputs {
            data: self.input_data.clone(),
            result: self.result.clone(),
        });
        prover.prove(trace).unwrap()
    }

    /// Prints all input parameters (from proof_size.md) for the current run.
    pub fn print_input_parameters(&self, trace_length: usize) {
        let n = trace_length;
        let w = TABLE_WIDTH;
        let q = self.options.num_queries();
        let blowup = self.options.blowup_factor();
        let fri = self.options.to_fri_options();
        let ff = fri.folding_factor();
        let r = fri.remainder_max_degree() + 1;
        let b = size_of::<BaseElement>();
        let d = size_of::<H::Digest>();
        let field_ext = match self.options.field_extension() {
            FieldExtension::None => "None",
            FieldExtension::Quadratic => "Quadratic",
            FieldExtension::Cubic => "Cubic",
        };
        let ext_degree = match self.options.field_extension() {
            FieldExtension::None => 1,
            FieldExtension::Quadratic => 2,
            FieldExtension::Cubic => 3,
        };
        let b_e = b * ext_degree;

        println!("\n=====================");
        println!("INPUT PARAMETERS (proof_size.md)");
        println!("=====================");
        println!("  N (trace length)           = {}", n);
        println!("  W (trace width)           = {}", w);
        println!("  Q (num_queries)            = {}", q);
        println!("  blowup                    = {}", blowup);
        println!("  grinding_factor           = {}", self.options.grinding_factor());
        println!("  field_extension           = {}", field_ext);
        println!("  ff (FRI folding factor)    = {}", ff);
        println!("  remainder_max_degree      = {}  (R = remainder_max_degree + 1 = {})", fri.remainder_max_degree(), r);
        println!("  B (base field elem bytes) = {}", b);
        println!("  D (digest size bytes)     = {}", d);

        // Вычисленные константы (по формулам из proof_size.md)
        let n_lde = n * blowup;
        let depth_lde = n_lde.ilog2() as usize;
        let d_max = 2 * (n - 1) + (n / PROGRAM_LEN) * (PROGRAM_LEN - 1);
        let c_cols = core::cmp::max(1, (d_max - (n - 1)).div_ceil(n));
        let max_remainder_size = r * blowup;
        let mut domain_size = n_lde;
        let mut l = 0;
        while domain_size > max_remainder_size {
            domain_size /= ff;
            l += 1;
        }
        const C_CTX_ESTIMATE: usize = 128;
        let num_trace_segments = 1usize;

        println!("---------------------");
        println!("ВЫЧИСЛЕННЫЕ КОНСТАНТЫ (derived, proof_size.md)");
        println!("---------------------");
        println!("  N_LDE                     = N * blowup = {}", n_lde);
        println!("  depth_LDE                 = log2(N_LDE) = {}", depth_lde);
        println!("  D_max                     = 2*(N-1) + (N/P)*(P-1) = {}  (P=PROGRAM_LEN)", d_max);
        println!("  C_cols                    = max(1, ceil((D_max-(N-1))/N)) = {}", c_cols);
        println!("  R                         = remainder_max_degree + 1 = {}", r);
        println!("  B_E                       = B * ext_degree = {}", b_e);
        println!("  max_remainder_size        = R * blowup = {}", max_remainder_size);
        println!("  L (num FRI layers)         = (Winterfell num_fri_layers) = {}", l);
        println!("  num_trace_segments        = {} (single-segment)", num_trace_segments);
        println!("  C_ctx (estimate)           = {} bytes", C_CTX_ESTIMATE);

        let expected_bytes = self.expected_proof_size_bytes(trace_length);
        println!("---------------------");
        println!("  Expected proof size       = {} bytes  ({:.2} KB)  (upper bound, see below)", expected_bytes, expected_bytes as f64 / 1024.0);
        println!("=====================\n");
    }

    pub fn new(string_length: usize, options: ProofOptions) -> Self {
        #[cfg(feature = "std")]
        let input = random_ascii_string(string_length);
        #[cfg(not(feature = "std"))]
        let input = "a".repeat(string_length);
        Self::from_input_string(input, options, true)
    }

    /// Builds the example from an explicit UTF-8 string (length should match the intended trace).
    /// When `log_sha256` is false, padding length is not printed (for batch/stat runs).
    pub fn from_input_string(input_string: String, options: ProofOptions, log_sha256: bool) -> Self {
        let prep = if log_sha256 {
            prepare_sha_256_block(&input_string)
        } else {
            prepare_sha_256_block_silent(&input_string)
        };
        let input_data = prep
            .chunks(16)
            .map(|chunk| {
                let arr: [BaseElement; 16] = chunk
                    .iter()
                    .cloned()
                    .collect::<Vec<BaseElement>>()
                    .try_into()
                    .expect("Chunk should have exactly 16 elements");
                arr
            })
            .collect::<Vec<[BaseElement; 16]>>();
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(input_string.as_bytes());
        let hash_result = hasher.finalize();
        if log_sha256 {
            println!("sha256(input_string) = {}", hex::encode(hash_result));
        }
        ExperimentShaExample {
            options,
            input_data,
            result: bytes_to_elements(hash_result.as_slice()),
            _hasher: PhantomData,
        }
    }
}

// EXAMPLE IMPLEMENTATION
// ================================================================================================

impl<H: ElementHasher> Example for ExperimentShaExample<H>
where
    H: ElementHasher<BaseField = BaseElement> + Sync,
    H::Digest: Default,
{
    fn prove(&self) -> Proof {
        // create a prover
        let prover = ExperimentShaProver::<H>::new(self.options.clone());

        // generate execution trace
        let trace =
            info_span!("generate_execution_trace", num_cols = TABLE_WIDTH, steps = field::Empty)
                .in_scope(|| {
                    let trace = prover.build_trace( PublicInputs { data: self.input_data.clone(), result: self.result.clone() } );
                    tracing::Span::current().record("steps", trace.length());
                    trace
                });

        self.print_input_parameters(trace.length());

        // generate the proof
        prover.prove(trace).unwrap()
    }

    fn verify(&self, proof: Proof) -> Result<(), VerifierError> {
        let acceptable_options =
            winterfell::AcceptableOptions::OptionSet(vec![proof.options().clone()]);

        winterfell::verify::<ExperimentShaAir, H, DefaultRandomCoin<H>, MerkleTree<H>>(
            proof,
            PublicInputs { data: self.input_data.clone(), result: self.result.clone() },
            &acceptable_options,
        )
    }

    fn verify_with_wrong_inputs(&self, proof: Proof) -> Result<(), VerifierError> {
        let acceptable_options =
            winterfell::AcceptableOptions::OptionSet(vec![proof.options().clone()]);
        let input_string = "WRONG".to_string();
        let input_data = prepare_sha_256_block(&input_string)
            .chunks(16)
            .map(|chunk| {
                let arr: [BaseElement; 16] = chunk
                    .iter()
                    .cloned()
                    .collect::<Vec<BaseElement>>()
                    .try_into()
                    .expect("Chunk should have exactly 16 elements");
                arr
            })
            .collect::<Vec<[BaseElement; 16]>>();

        winterfell::verify::<ExperimentShaAir, H, DefaultRandomCoin<H>, MerkleTree<H>>(
            proof,
            PublicInputs { data: input_data, result: self.result.clone() },
            &acceptable_options,
        )
    }

    fn expected_proof_breakdown(&self, trace_length: usize) -> Option<ExpectedProofBreakdown> {
        Some(self.compute_expected_breakdown(trace_length))
    }

    fn expected_proof_breakdown_for_comparison(
        &self,
        trace_length: usize,
        actual_context_size: usize,
        actual_fri_layers: usize,
        actual_num_unique_queries: usize,
    ) -> Option<ExpectedProofBreakdown> {
        Some(self.compute_expected_breakdown_with_actuals(
            trace_length,
            actual_context_size,
            actual_fri_layers,
            actual_num_unique_queries,
        ))
    }

    fn print_formula_proof_size_estimates(
        &self,
        proof: &Proof,
        decomposition: &ProofDecomposition,
        _proof_serialized_len: usize,
    ) {
        let n = proof.trace_info().length();
        if let Some(expected) = self.expected_proof_breakdown_for_comparison(
            n,
            decomposition.context_size,
            decomposition.fri_decomposition.num_layers,
            proof.num_unique_queries as usize,
        ) {
            expected.print_labeled_estimate(
                "experiment_sha: предполагаемые размеры (формулы, context/L/Q из proof)",
            );
        }
        decomposition.print_actual_component_table("experiment_sha: реальные размеры (сериализация proof)");

        let fri = self.options.to_fri_options();
        let b_e = match self.options.field_extension() {
            FieldExtension::None => size_of::<BaseElement>(),
            FieldExtension::Quadratic => 2 * size_of::<BaseElement>(),
            FieldExtension::Cubic => 3 * size_of::<BaseElement>(),
        };
        print_fri_layers_merkle_and_query_stats(proof, decomposition, fri.folding_factor(), b_e);
    }
}
