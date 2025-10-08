// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use winterfell::{
    crypto::MerkleTree, matrix::ColMatrix, AuxRandElements, CompositionPoly, CompositionPolyTrace, ConstraintCompositionCoefficients, DefaultConstraintCommitment, DefaultConstraintEvaluator, DefaultTraceLde, PartitionOptions, StarkDomain, Trace, TraceInfo, TracePolyTable, TraceTable
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
}

impl<H: ElementHasher> ExperimentShaProver<H> {
    pub fn new(options: ProofOptions) -> Self {
        Self { options, _hasher: PhantomData }
    }

    /// Builds an execution trace for computing a sequence of the specified length
    pub fn build_trace(&self, input_data: PublicInputs) -> TraceTable<BaseElement> {
        let program = get_program();
        assert_eq!(program.len(), PROGRAM_LEN);
        assert_eq!(input_data.result.len(), 8);
        println!("input_data.data.len() = {}", input_data.data.len());
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
                    if step == program.len() * input_data.data.len() - 2 {
                        println!("Proof result is sha256(input_string) = {}", hex::encode(extract_hash(state)));
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
}