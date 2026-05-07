// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use core::mem::size_of;

use fri::FriOptions;
use winterfell::{
    crypto::MerkleTree,
    matrix::ColMatrix,
    AuxRandElements, CompositionPoly, CompositionPolyTrace, ConstraintCompositionCoefficients,
    DefaultConstraintCommitment, DefaultConstraintEvaluator, DefaultTraceLde, PartitionOptions,
    StarkDomain, Trace, TraceInfo, TracePolyTable, TraceTable,
};

use crate::experiment_sha::fri_digest_stats::{
    expected_fri_digest_per_layer, expected_merkle_batch_digest_uniform, FriDigestRunRecorder,
    FriDigestStatsRow,
};
use crate::experiment_sha::table_constants::{INPUT_BASE_ELEMENTS, IV_INDICES};

use crate::experiment_sha::vm_program::{AddStep1, AddStep2, SetR10, SetR11, SetR11Value};
use crate::experiment_sha::{air::PublicInputs, table::set_iv, utis::{element_to_u32, extract_hash, get_iv}, vm_program::{get_program, Command, FromBin, SetB, ToBin, AND, NOP, NOT, PROGRAM_LEN, ROR, SHR, XOR, ResetHardMemory}};
use crate::experiment_sha::table_constants::TABLE_WIDTH;

use super::{
    BaseElement, DefaultRandomCoin, ElementHasher, ExperimentShaAir, FieldElement, PhantomData,
    ProofOptions, Prover,
};



// EXPERIMENT SHA PROVER
// ================================================================================================

pub struct ExperimentShaProver<H: ElementHasher> {
    options: ProofOptions,
    _hasher: PhantomData<H>,
    fri_digest_recorder: Option<FriDigestRunRecorder>,
    quiet_diagnostics: bool,
}

impl<H: ElementHasher> ExperimentShaProver<H> {
    pub fn new(options: ProofOptions) -> Self {
        Self {
            options,
            _hasher: PhantomData,
            fri_digest_recorder: None,
            quiet_diagnostics: false,
        }
    }

    /// Collect FRI Merkle batch digest counts into `recorder` (typically with a shared `Arc` across runs).
    /// When `quiet_diagnostics` is true, `println` diagnostics in trace hooks are suppressed.
    pub fn new_with_fri_digest_recorder(
        options: ProofOptions,
        recorder: FriDigestRunRecorder,
        quiet_diagnostics: bool,
    ) -> Self {
        Self {
            options,
            _hasher: PhantomData,
            fri_digest_recorder: Some(recorder),
            quiet_diagnostics,
        }
    }

    fn log_diag(&self) -> bool {
        !self.quiet_diagnostics
    }

    /// Builds an execution trace for computing a sequence of the specified length
    pub fn build_trace(&self, input_data: PublicInputs) -> TraceTable<BaseElement> {
        let program = get_program();
        assert_eq!(program.len(), PROGRAM_LEN);
        assert_eq!(input_data.result.len(), 8);
        if self.log_diag() {
            println!("input_data.data.len() = {}", input_data.data.len());
        }
        let mut trace = TraceTable::new(TABLE_WIDTH, program.len() * input_data.data.len());
        trace.fill(
            |state| {
                for i in 0..input_data.data[0].len() {
                    state[i] = input_data.data[0][i];
                }
                set_iv(state, get_iv());

                
                // println!("initial w");
                // println!("{:?}", state[0..64].iter().map(|x| format!("{:x}", element_to_u32(*x))).collect::<Vec<String>>().join(" "));

                // println!("initial h");
                // println!("{:?}", state[64..72].iter().map(|x| format!("{:x}", element_to_u32(*x))).collect::<Vec<String>>().join(" "));
            },
            |step: usize, state: &mut [BaseElement]| {
                if step % program.len() == program.len() - 1 {
                    for i in 0..input_data.data[(step + 1) / program.len()].len() {
                        state[i] = input_data.data[(step + 1) / program.len()][i];
                    }
                } else {
                    let mut initial_state = vec![BaseElement::new(0); state.len()];
                    for i in 0..state.len() {
                        initial_state[i] = state[i];
                    }
                    for [command, b1] in program[step % program.len()].clone() {
                        if ToBin::num() == command {
                            ToBin::prove(&initial_state, state, element_to_u32(b1) as usize);
                        } else if FromBin::num() == command {
                            FromBin::prove(&initial_state, state, element_to_u32(b1) as usize);
                            /*
                            if b1 == BaseElement::new(0) {
                                println!("w[0] = {:x}", element_to_u32(state[0]));
                            }
                            */
                        } else if XOR::num() == command {
                            XOR::prove(&initial_state, state, element_to_u32(b1) as usize);
                        } else if AND::num() == command {
                            AND::prove(&initial_state, state, element_to_u32(b1) as usize);
                        } else if NOT::num() == command {
                            NOT::prove(&initial_state, state, element_to_u32(b1) as usize);
                        } else if ROR::num() == command {
                            ROR::prove(&initial_state, state, element_to_u32(b1) as usize);
                        } else if SHR::num() == command {
                            SHR::prove(&initial_state, state, element_to_u32(b1) as usize);
                        } else if AddStep1::num() == command {
                            AddStep1::prove(&initial_state, state, element_to_u32(b1) as usize);
                        } else if AddStep2::num() == command {
                            AddStep2::prove(&initial_state, state, element_to_u32(b1) as usize);
                        } else if SetB::num() == command {
                            SetB::prove(&initial_state, state, element_to_u32(b1) as usize);
                        } else if NOP::num() == command {
                            NOP::prove(&initial_state, state, element_to_u32(b1) as usize);
                        } else if ResetHardMemory::num() == command {
                            ResetHardMemory::prove(&initial_state, state, element_to_u32(b1) as usize);
                        } else if SetR10::num() == command {
                            SetR10::prove(&initial_state, state, element_to_u32(b1) as usize);
                        } else if SetR11::num() == command {
                            SetR11::prove(&initial_state, state, element_to_u32(b1) as usize);
                        } else if SetR11Value::num() == command {
                            SetR11Value::prove(&initial_state, state, element_to_u32(b1) as usize);
                        } else {
                            todo!();
                        }
                    }
                    if step == program.len() * input_data.data.len() - 2 && self.log_diag() {
                        println!(
                            "Proof result is sha256(input_string) = {}",
                            hex::encode(extract_hash(state))
                        );
                    }
                }
            }
        );

        trace
    }
}

impl<H: ElementHasher> Prover for ExperimentShaProver<H>
where
    H: ElementHasher<BaseField = BaseElement> + Sync,
{
    type BaseField = BaseElement;
    type Air = ExperimentShaAir;
    type Trace = TraceTable<BaseElement>;
    type HashFn = H;
    type VC = MerkleTree<H>;
    type RandomCoin = DefaultRandomCoin<Self::HashFn>;
    type TraceLde<E: FieldElement<BaseField = Self::BaseField>> =
        DefaultTraceLde<E, Self::HashFn, Self::VC>;
    type ConstraintCommitment<E: FieldElement<BaseField = Self::BaseField>> =
        DefaultConstraintCommitment<E, H, Self::VC>;
    type ConstraintEvaluator<'a, E: FieldElement<BaseField = Self::BaseField>> =
        DefaultConstraintEvaluator<'a, Self::Air, E>;

    fn get_pub_inputs(&self, trace: &Self::Trace) -> PublicInputs {
        let mut input_data_elements: Vec<[BaseElement; 16]> = vec![[BaseElement::new(0); 16]; trace.length() / PROGRAM_LEN];
        for j in 0..trace.length() / PROGRAM_LEN {
            for i in 0..INPUT_BASE_ELEMENTS {
                input_data_elements[j][i] = trace.get(i, j * PROGRAM_LEN);
            }
        }
        let mut result_elements = Vec::new();
        for i in 0..8 {
            result_elements.push(trace.get(IV_INDICES[i], trace.length() - 1));
        }
        // println!("input_data_elements: {:?}", input_data_elements[0]);
        PublicInputs{ data: input_data_elements, result: result_elements }
    }

    fn options(&self) -> &ProofOptions {
        &self.options
    }

    fn new_trace_lde<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        trace_info: &TraceInfo,
        main_trace: &ColMatrix<Self::BaseField>,
        domain: &StarkDomain<Self::BaseField>,
        partition_option: PartitionOptions,
    ) -> (Self::TraceLde<E>, TracePolyTable<E>) {
        DefaultTraceLde::new(trace_info, main_trace, domain, partition_option)
    }

    fn new_evaluator<'a, E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        air: &'a Self::Air,
        aux_rand_elements: Option<AuxRandElements<E>>,
        composition_coefficients: ConstraintCompositionCoefficients<E>,
    ) -> Self::ConstraintEvaluator<'a, E> {
        DefaultConstraintEvaluator::new(air, aux_rand_elements, composition_coefficients)
    }

    fn build_constraint_commitment<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        composition_poly_trace: CompositionPolyTrace<E>,
        num_constraint_composition_columns: usize,
        domain: &StarkDomain<Self::BaseField>,
        partition_options: PartitionOptions,
    ) -> (Self::ConstraintCommitment<E>, CompositionPoly<E>) {
        DefaultConstraintCommitment::new(
            composition_poly_trace,
            num_constraint_composition_columns,
            domain,
            partition_options,
        )
    }

    fn on_query_positions_determined(
        &self,
        query_positions: &[usize],
        lde_domain_size: usize,
        fri_options: &FriOptions,
    ) {
        let q = query_positions.len();
        let ff = fri_options.folding_factor();
        let d = size_of::<H::Digest>();
        let h_lde = lde_domain_size.ilog2() as usize;
        let batch_ov = 2 + q;
        let trace_exp_digest_nodes = expected_merkle_batch_digest_uniform(h_lde, q);
        let trace_paths = trace_exp_digest_nodes.saturating_mul(d).saturating_add(batch_ov);

        if self.log_diag() {
            println!("\n=== experiment_sha (во время prove): trace/constraint batch paths (ожид., модель) ===");
            println!("Q = {}, |H| = {} B, η = {}", q, d, ff);
            println!(
                "Trace / constraint LDE batch paths (ожид., байты): {} B = E_nodes·|H| + {}, где E_nodes = Σ_{{d=1}}^{{h-2}} 2^d(1-(1-2^-d)^Q) (без уровня у листьев), h=⌊log₂ N_LDE⌋",
                trace_paths, batch_ov
            );
            println!(
                "Trace / constraint Merkle: листьев дерева (ожид.) = N_LDE = {}; digest-узлов в batch E_nodes = {}",
                lde_domain_size, trace_exp_digest_nodes
            );

            println!("\nFRI по слоям — ожидание (fold_positions → Q_i; E_nodes(h,Q_i), сумма d=1..h-2, без слоя у листьев):");
            println!(
                "{:<6} {:>6} {:>16} {:>10} {:>18}",
                "слой", "глуб.", "листьев дерева", "Q_i ожид.", "digest узлов ожид."
            );
            println!("{}", "-".repeat(60));
            let exp_rows = expected_fri_digest_per_layer(lde_domain_size, query_positions, fri_options);
            for (layer_idx, &(merkle_leaves, qi, exp_digest_nodes)) in exp_rows.iter().enumerate() {
                let h = merkle_leaves.ilog2() as usize;
                println!(
                    "{:<6} {:>6} {:>16} {:>10} {:>18}",
                    layer_idx, h, merkle_leaves, qi, exp_digest_nodes
                );
            }
            println!("(факт по слоям — в блоке «FRI Merkle — факт» ниже, после build_proof)\n");
        }
    }

    fn on_fri_proof_built<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        fri_proof: &fri::FriProof,
        lde_domain_size: usize,
        fri_options: &FriOptions,
        query_positions: &[usize],
    ) {
        let ff = fri_options.folding_factor();
        let expected = expected_fri_digest_per_layer(lde_domain_size, query_positions, fri_options);

        if let Some(ref rec) = self.fri_digest_recorder {
            let mut rows = rec.rows.lock().expect("fri stats mutex");
            for (i, layer) in fri_proof.layers().iter().enumerate() {
                let s = layer
                    .merkle_opening_stats::<E, H>(ff)
                    .expect("FRI layer merkle stats");
                let (merkle_leaves_f, qi_e, digest_e) = expected
                    .get(i)
                    .copied()
                    .unwrap_or((0, 0, 0));
                rows.push(FriDigestStatsRow {
                    run: rec.run,
                    layer: i,
                    digest_cells_actual: s.batch_internal_digest_cells,
                    digest_cells_expected: digest_e,
                    opened_leaves: s.num_opened_leaves,
                    tree_leaf_capacity: s.tree_leaf_capacity,
                    merkle_depth: s.merkle_depth,
                    merkle_leaves_formula: merkle_leaves_f,
                    qi_expected: qi_e,
                });
            }
        }

        if self.log_diag() {
            println!("\n=== experiment_sha (во время prove): FRI Merkle — факт из `FriProver::build_proof` ===");
            println!(
                "{:<6} {:>6} {:>16} {:>14} {:>18}",
                "слой",
                "глуб.",
                "листьев дерева",
                "открыто листьев",
                "digest в batch"
            );
            println!("{}", "-".repeat(66));
            for (i, layer) in fri_proof.layers().iter().enumerate() {
                let s = layer
                    .merkle_opening_stats::<E, H>(ff)
                    .expect("FRI layer merkle stats");
                println!(
                    "{:<6} {:>6} {:>16} {:>14} {:>18}",
                    i,
                    s.merkle_depth,
                    s.tree_leaf_capacity,
                    s.num_opened_leaves,
                    s.batch_internal_digest_cells
                );
            }
            println!();
        }
    }
}