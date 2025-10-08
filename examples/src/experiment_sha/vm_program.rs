use crate::{experiment_sha::{table::{and_bit_registers, not_bit_registers, ror_bit_registers, set_from_bit_register, set_to_bit_register, shr_bit_registers, xor_bit_registers}, utis::element_to_u32}, utils::{are_equal, EvaluationResult}};

use crate::experiment_sha::transitions_constants::*;
use crate::experiment_sha::table_constants::*;

use super::{BaseElement, FieldElement};

pub trait Command {
    fn num() -> BaseElement;
    fn eval_transitions<E: FieldElement + From<BaseElement>>(transitions: &mut [E], current_frame: &[E], next_frame: &[E], periodic_values: &[E]);
    fn prove(initial_state: &[BaseElement], final_state: &mut [BaseElement], b1: usize);
}

pub struct ToBin;
impl ToBin {
    fn eval_single_transition<E: FieldElement + From<BaseElement>>(current_frame: &[E], next_frame: &[E], idx: usize) -> E{
        let two = E::from(BaseElement::new(2));
        let mut p = E::from(BaseElement::new(1));
        let mut in_register = E::from(BaseElement::new(0));
        for i in B1 {
            in_register += next_frame[i] * p;
            p = two * p;
        }
        in_register - current_frame[idx]
    }
}

impl Command for ToBin {
    fn num() -> BaseElement {
        BaseElement::new(0)
    }
    fn eval_transitions<E: FieldElement + From<BaseElement>>(transitions: &mut [E], current_frame: &[E], next_frame: &[E], periodic_values: &[E]){
        for i in 0..TO_B1_TRANSITIONS_LEN {
            let flag = periodic_values[PERIODIC_TO_B1_COLUMNS_INDICES[i]];
            let constraint_value = ToBin::eval_single_transition(current_frame, next_frame, i);            
            transitions.agg_constraint(TO_B1_TRANSITIONS_INDICES[i], flag, constraint_value);
        }
        
    }
    
    fn prove(_: &[BaseElement], final_state: &mut [BaseElement], b1: usize) {
        set_to_bit_register(final_state, final_state[b1], B1);
    }
}

pub struct FromBin;

impl FromBin {
    fn eval_single_transition<E: FieldElement + From<BaseElement>>(next_frame: &[E], idx: usize) -> E {
        let two = E::from(BaseElement::new(2));
        let mut p = E::from(BaseElement::new(1));
        let mut in_register = E::from(BaseElement::new(0));
        for i in B1 {
            in_register += next_frame[i] * p;
            p = two * p;
        }
        in_register - next_frame[idx]
    }
}


impl Command for FromBin {
    fn num() -> BaseElement {
        BaseElement::new(1)
    }
    fn eval_transitions<E: FieldElement + From<BaseElement>>(transitions: &mut [E], _: &[E], next_frame: &[E], periodic_values: &[E]) {
        for i in 0..FROM_BIN_TRANSITIONS_LEN {            
            let flag = periodic_values[PERIODIC_FROM_BIN_COLUMNS_INDICES[i]];
            let constraint_value = FromBin::eval_single_transition(next_frame, i);
            transitions.agg_constraint(FROM_BIN_TRANSITIONS_INDICES[i], flag, constraint_value);
        }
    }
    
    fn prove(_: &[BaseElement], final_state: &mut [BaseElement], b1: usize) {
        set_from_bit_register(final_state, b1, B1);
    }
}

pub struct XOR;

impl XOR {
    fn eval_single_transition<E: FieldElement + From<BaseElement>>(current_frame: &[E], next_frame: &[E], idx: usize) -> E {
        let two = E::from(BaseElement::new(2));
        let mut p = E::from(BaseElement::new(1));
        let mut in_register = E::from(BaseElement::new(0));
        for i in B1 {
            in_register += (current_frame[i] + next_frame[i] - E::from(BaseElement::new(2)) * current_frame[i] * next_frame[i]) * p;
            p = two * p;
        }
        in_register - next_frame[idx]
    }
}

impl Command for XOR {
    fn num() -> BaseElement {
        BaseElement::new(2)
    }
    
    fn eval_transitions<E: FieldElement + From<BaseElement>>(transitions: &mut [E], current_frame: &[E], next_frame: &[E], periodic_values: &[E]) {
        for i in 0..XOR_TRANSITIONS_LEN {
            let flag = periodic_values[PERIODIC_XOR_COLUMNS_INDICES[i]];
            let constraint_value = XOR::eval_single_transition(current_frame, next_frame, REGISTERS_INDICES[i]);
            transitions.agg_constraint(XOR_TRANSITIONS_INDICES[i], flag, constraint_value);
        }
    }
    
    fn prove(initial_state: &[BaseElement], final_state: &mut [BaseElement], idx: usize) {
        xor_bit_registers(initial_state, final_state, idx);
    }
}

pub struct AND;

impl AND {
    fn eval_single_transition<E: FieldElement + From<BaseElement>>(current_frame: &[E], next_frame: &[E], idx: usize) -> E {
        let two = E::from(BaseElement::new(2));
        let mut p = E::from(BaseElement::new(1));
        let mut in_register = E::from(BaseElement::new(0));
        for i in B1 {
            in_register += (current_frame[i] * next_frame[i]) * p;
            p = two * p;
        }
        in_register - next_frame[idx]
    }
}

impl Command for AND {
    fn num() -> BaseElement {
        BaseElement::new(3)
    }
    
    fn eval_transitions<E: FieldElement + From<BaseElement>>(transitions: &mut [E], current_frame: &[E], next_frame: &[E], periodic_values: &[E]) {
        for i in 0..AND_TRANSITIONS_LEN {
            let flag = periodic_values[PERIODIC_AND_COLUMNS_INDICES[i]];
            let constraint_value = AND::eval_single_transition(current_frame, next_frame, REGISTERS_INDICES[i]);
            transitions.agg_constraint(AND_TRANSITIONS_INDICES[i], flag, constraint_value);
        }
    }
    
    fn prove(initial_state: &[BaseElement], final_state: &mut [BaseElement], idx: usize) {
        and_bit_registers(initial_state, final_state, idx);
    }
}

pub struct NOT;

impl NOT {
    fn eval_single_transition<E: FieldElement + From<BaseElement>>(current_frame: &[E], next_frame: &[E], idx: usize) -> E {
        let b1_current = current_frame[B1[idx]];
        let b1_next = next_frame[B1[idx]];
        let not_result = E::from(BaseElement::new(1)) - b1_current;
        
        b1_next - not_result
    }
}

impl Command for NOT {
    fn num() -> BaseElement {
        BaseElement::new(4)
    }
    
    fn eval_transitions<E: FieldElement + From<BaseElement>>(transitions: &mut [E], current_frame: &[E], next_frame: &[E], periodic_values: &[E]) {
        let flag = periodic_values[PERIODIC_NOT_COLUMNS_INDICES[0]];
        for i in 0..NOT_TRANSITIONS_LEN {
            let constraint_value = NOT::eval_single_transition(current_frame, next_frame, i);
            transitions.agg_constraint(NOT_TRANSITIONS_INDICES[i], flag, constraint_value);
        }
    }
    
    fn prove(_: &[BaseElement], final_state: &mut [BaseElement], _: usize) {
        // Выполняем NOT для B1, результат сохраняем в B1
        not_bit_registers(final_state);
    }
}

pub struct ROR;

impl ROR {
    fn eval_single_transition<E: FieldElement + From<BaseElement>>(current_frame: &[E], next_frame: &[E], idx: usize) -> E {
        let two = E::from(BaseElement::new(2));
        let mut p = E::from(BaseElement::new(1));
        let mut current_register = E::from(BaseElement::new(0));
        for i in 0..B1.len() {
            current_register += current_frame[B1[(i + idx) % B1.len()]] * p;
            p = two * p;
        }

        p = E::from(BaseElement::new(1));
        let mut next_register = E::from(BaseElement::new(0));
        for i in B1 {
            next_register += next_frame[i] * p;
            p = two * p;
        }
        next_register - current_register
    }
}

impl Command for ROR {
    fn num() -> BaseElement {
        BaseElement::new(5)
    }
    
    fn eval_transitions<E: FieldElement + From<BaseElement>>(transitions: &mut [E], current_frame: &[E], next_frame: &[E], periodic_values: &[E]) {
        for i in 0..ROR_TRANSITIONS_LEN {
            let flag = periodic_values[PERIODIC_ROR_COLUMNS_INDICES[i]];
            let constraint_value = ROR::eval_single_transition(current_frame, next_frame, ROR_TRANSITIONS_SHIFTS[i]);
            transitions.agg_constraint(ROR_TRANSITIONS_INDICES[i], flag, constraint_value);
        }
    }
    
    fn prove(_: &[BaseElement], final_state: &mut [BaseElement], shift: usize) {
        // Выполняем циклический сдвиг вправо для B1, результат сохраняем в B1
        ror_bit_registers(final_state, shift);
    }
}

pub struct SHR;

impl SHR {
    fn eval_single_transition<E: FieldElement + From<BaseElement>>(current_frame: &[E], next_frame: &[E], idx: usize) -> E {
        let b1_next = next_frame[B1[idx]];
        let expected_value = if idx == 31 {
            E::from(BaseElement::new(0))
        } else {
            current_frame[B1[idx + 1]]
        };
        
        b1_next - expected_value
    }
}

impl Command for SHR {
    fn num() -> BaseElement {
        BaseElement::new(6)
    }
    
    fn eval_transitions<E: FieldElement + From<BaseElement>>(transitions: &mut [E], current_frame: &[E], next_frame: &[E], periodic_values: &[E]) {
        let flag = periodic_values[PERIODIC_SHR_COLUMNS_INDICES[0]];
        
        // Обрабатываем SHR transitions
        for i in 0..SHR_TRANSITIONS_LEN {
            let constraint_value = SHR::eval_single_transition(current_frame, next_frame, i);
            transitions.agg_constraint(SHR_TRANSITIONS_INDICES[i], flag, constraint_value);
        }
    }
    
    fn prove(_: &[BaseElement], final_state: &mut [BaseElement], _: usize) {
        // Выполняем сдвиг вправо (деление на 2) для B1, результат сохраняем в B1
        shr_bit_registers(final_state);
    }
}

pub struct AddStep1;

impl Command for AddStep1 {
    fn num() -> BaseElement {
        BaseElement::new(7)
    }
    
    fn eval_transitions<E: FieldElement + From<BaseElement>>(transitions: &mut [E], current_frame: &[E], next_frame: &[E], periodic_values: &[E]) {
        let flag = periodic_values[PERIODIC_ADD_1_COLUMNS_INDICES[0]];
        let two = E::from(BaseElement::new(2));
        let mut p = E::from(BaseElement::new(1));
        let mut in_register = E::from(BaseElement::new(0));
        for i in 0..B1.len()-1 {
            in_register += current_frame[B1[i]] * p;
            p = two * p;
        }
        transitions.agg_constraint(ADD_1_TRANSITIONS_INDICES[0], flag, in_register - current_frame[REGISTERS_INDICES[10]]);
        
        p = E::from(BaseElement::new(1));
        in_register = E::from(BaseElement::new(0));
        for i in 0..B1.len()-1 {
            in_register += next_frame[B1[i]] * p;
            p = two * p;
        }
        transitions.agg_constraint(ADD_1_TRANSITIONS_INDICES[1], flag, in_register - current_frame[REGISTERS_INDICES[11]]);
        transitions.agg_constraint(ADD_1_TRANSITIONS_INDICES[2], flag, next_frame[REGISTERS_INDICES[10]] - (current_frame[REGISTERS_INDICES[10]] + current_frame[REGISTERS_INDICES[11]]));
        transitions.agg_constraint(ADD_1_TRANSITIONS_INDICES[3], flag, are_equal(next_frame[REGISTERS_INDICES[11]], current_frame[B1[B1.len() - 1]] + next_frame[B1[B1.len() - 1]] - E::from(BaseElement::new(2)) * current_frame[B1[B1.len() - 1]] * next_frame[B1[B1.len() - 1]]));
    }
    
    fn prove(initial_state: &[BaseElement], final_state: &mut [BaseElement], _: usize) {
        final_state[REGISTERS_INDICES[10]] = BaseElement::new((element_to_u32(initial_state[REGISTERS_INDICES[10]]) as u64 + element_to_u32(initial_state[REGISTERS_INDICES[11]]) as u64) as u64);
        final_state[REGISTERS_INDICES[11]] = BaseElement::new((element_to_u32(initial_state[B1[BIT_REGISTERS_LEN - 1]]) ^ element_to_u32(final_state[B1[BIT_REGISTERS_LEN - 1]])) as u64);    
    }
}

pub struct AddStep2;

impl Command for AddStep2 {
    fn num() -> BaseElement {
        BaseElement::new(8)
    }
    
    fn eval_transitions<E: FieldElement + From<BaseElement>>(transitions: &mut [E], current_frame: &[E], next_frame: &[E], periodic_values: &[E]) {
        for i in 0..PERIODIC_ADD_2_COLUMNS_LEN {
            let flag = periodic_values[PERIODIC_ADD_2_COLUMNS_INDICES[i]];
            let two = E::from(BaseElement::new(2));
            let mut p = E::from(BaseElement::new(1));
            let mut in_register = E::from(BaseElement::new(0));
            for i in 0..B1.len()-1 {
                in_register += next_frame[B1[i]] * p;
                p = two * p;
            }
            transitions.agg_constraint(ADD_2_TRANSITIONS_INDICES[0], flag, in_register - next_frame[REGISTERS_INDICES[10]]);

            transitions.agg_constraint(ADD_2_TRANSITIONS_INDICES[1], flag, are_equal(next_frame[REGISTERS_INDICES[11]],E::from(BaseElement::new(1 << 31)) * (next_frame[B1[B1.len() - 1]] + current_frame[REGISTERS_INDICES[11]] - E::from(BaseElement::new(2)) * current_frame[REGISTERS_INDICES[11]] * next_frame[B1[B1.len() - 1]])));

            transitions.agg_constraint(ADD_2_TRANSITIONS_INDICES[2 + i], flag, are_equal(next_frame[REGISTERS_INDICES[i]], next_frame[REGISTERS_INDICES[10]] + next_frame[REGISTERS_INDICES[11]]));
        }
    }
    
    fn prove(initial_state: &[BaseElement], final_state: &mut [BaseElement], idx: usize) {
        final_state[REGISTERS_INDICES[10]] = BaseElement::new((element_to_u32(initial_state[REGISTERS_INDICES[10]]) & ((1u32 << 31) - 1)) as u64);
        final_state[REGISTERS_INDICES[11]] = BaseElement::new(((element_to_u32(final_state[B1[BIT_REGISTERS_LEN - 1]]) ^ element_to_u32(initial_state[REGISTERS_INDICES[11]])) << 31) as u64);
        final_state[idx] = final_state[REGISTERS_INDICES[10]] + final_state[REGISTERS_INDICES[11]]; 
    }
}

pub struct SetB;

impl SetB {
    fn eval_single_transition<E: FieldElement + From<BaseElement>>(next_frame: &[E], periodic_values: &[E]) -> E {
        let two = E::from(BaseElement::new(2));
        let mut p = E::from(BaseElement::new(1));
        let mut in_register = E::from(BaseElement::new(0));
        for i in B1 {
            in_register += next_frame[i] * p;
            p = two * p;
        }
        in_register - periodic_values[0]
    }
}


impl Command for SetB {
    fn num() -> BaseElement {
        BaseElement::new(9)
    }
    
    fn eval_transitions<E: FieldElement + From<BaseElement>>(transitions: &mut [E], _: &[E], next_frame: &[E], periodic_values: &[E]) {
        let flag = periodic_values[PERIODIC_SETB2_COLUMNS_INDICES[0]];
    
        let constraint_value = SetB::eval_single_transition(next_frame, periodic_values);
        transitions.agg_constraint(SETB2_TRANSITIONS_INDICES[0], flag, constraint_value);
    }
    
    fn prove(_: &[BaseElement], final_state: &mut [BaseElement], value: usize) {
        let base_element_value = BaseElement::new(value as u64);
        set_to_bit_register(final_state, base_element_value, B1);
    }
}

pub struct NOP;

impl Command for NOP {
    fn num() -> BaseElement {
        BaseElement::new(10)
    }
    
    fn eval_transitions<E: FieldElement + From<BaseElement>>(_: &mut[E], _: &[E], _: &[E], _: &[E]) {
    }
    
    fn prove(_: &[BaseElement], _: &mut [BaseElement], _: usize) {
    }
}

pub struct ResetHardMemory;

impl Command for ResetHardMemory {
    fn num() -> BaseElement {
        BaseElement::new(11)
    }
    
    fn eval_transitions<E: FieldElement + From<BaseElement>>(_: &mut[E], _: &[E], _: &[E], _: &[E]) {
    }
    
    fn prove(_: &[BaseElement], _: &mut [BaseElement], _: usize) {
    }
}

pub struct SetR10;

impl Command for SetR10 {
    fn num() -> BaseElement {
        BaseElement::new(12)
    }
    
    fn eval_transitions<E: FieldElement + From<BaseElement>>(_: &mut[E], _: &[E], _: &[E], _: &[E]) {
    }
    
    fn prove(initial_state: &[BaseElement], final_state: &mut [BaseElement], idx: usize) {
        final_state[REGISTERS_INDICES[10]] = BaseElement::new((element_to_u32(initial_state[idx]) & ((1u32 << 31) - 1)) as u64);
    }
}

pub struct SetR11;

impl Command for SetR11 {
    fn num() -> BaseElement {
        BaseElement::new(13)
    }
    
    fn eval_transitions<E: FieldElement + From<BaseElement>>(_: &mut[E], _: &[E], _: &[E], _: &[E]) {
    }
    
    fn prove(initial_state: &[BaseElement], final_state: &mut [BaseElement], idx: usize) {
        final_state[REGISTERS_INDICES[11]] = BaseElement::new((element_to_u32(initial_state[idx]) & ((1u32 << 31) - 1)) as u64);
    }
}

pub struct SetR11Value;

impl Command for SetR11Value {
    fn num() -> BaseElement {
        BaseElement::new(14)
    }
    
    fn eval_transitions<E: FieldElement + From<BaseElement>>(_: &mut[E], _: &[E], _: &[E], _: &[E]) {
    }
    
    fn prove(_: &[BaseElement], final_state: &mut [BaseElement], value: usize) {
        final_state[REGISTERS_INDICES[11]] = BaseElement::new((value as u32 & ((1u32 << 31) - 1)) as u64);
    }
}


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

pub const PROGRAM_LEN: usize = 8192;

fn create_tmp_iv() -> Vec<Vec<[BaseElement; 2]>> {
    vec![
        vec![[ToBin::num(), BaseElement::new(IV_INDICES[0] as u64)],
             [FromBin::num(), BaseElement::new(REGISTERS_INDICES[0] as u64)]], // tmp_h[0]
        vec![[ToBin::num(), BaseElement::new(IV_INDICES[1] as u64)],
             [FromBin::num(), BaseElement::new(REGISTERS_INDICES[1] as u64)]], // tmp_h[1]
        vec![[ToBin::num(), BaseElement::new(IV_INDICES[2] as u64)],
             [FromBin::num(), BaseElement::new(REGISTERS_INDICES[2] as u64)]], // tmp_h[2]
        vec![[ToBin::num(), BaseElement::new(IV_INDICES[3] as u64)],
             [FromBin::num(), BaseElement::new(REGISTERS_INDICES[3] as u64)]], // tmp_h[3]
        vec![[ToBin::num(), BaseElement::new(IV_INDICES[4] as u64)],
             [FromBin::num(), BaseElement::new(REGISTERS_INDICES[4] as u64)]], // tmp_h[4]
        vec![[ToBin::num(), BaseElement::new(IV_INDICES[5] as u64)],
             [FromBin::num(), BaseElement::new(REGISTERS_INDICES[5] as u64)]], // tmp_h[5]
        vec![[ToBin::num(), BaseElement::new(IV_INDICES[6] as u64)],
             [FromBin::num(), BaseElement::new(REGISTERS_INDICES[6] as u64)]], // tmp_h[6]
        vec![[ToBin::num(), BaseElement::new(IV_INDICES[7] as u64)],
             [FromBin::num(), BaseElement::new(REGISTERS_INDICES[7] as u64)]]  // tmp_h[7]
    ]
}

// Set s1 to r8 register
fn calc_s1() -> Vec<Vec<[BaseElement; 2]>> {
    vec![
        vec![[ToBin::num(), BaseElement::new(REGISTERS_INDICES[4] as u64)]],
        vec![[ROR::num(), BaseElement::new(6)],
             [FromBin::num(), BaseElement::new(REGISTERS_INDICES[8] as u64)]],
        vec![[ToBin::num(), BaseElement::new(REGISTERS_INDICES[4] as u64)]],
        vec![[ROR::num(), BaseElement::new(11)],
             [FromBin::num(), BaseElement::new(REGISTERS_INDICES[9] as u64)]],
        vec![[ToBin::num(), BaseElement::new(REGISTERS_INDICES[4] as u64)]],
        vec![[ROR::num(), BaseElement::new(25)]],
        vec![[ToBin::num(), BaseElement::new(REGISTERS_INDICES[9] as u64)],
             [XOR::num(), BaseElement::new(REGISTERS_INDICES[9] as u64)]],
        vec![[ToBin::num(), BaseElement::new(REGISTERS_INDICES[9] as u64)]],
        vec![[ToBin::num(), BaseElement::new(REGISTERS_INDICES[8] as u64)],
             [XOR::num(), BaseElement::new(REGISTERS_INDICES[8] as u64)]],
    ]
}

// Set ch to r9 register
fn calc_ch() -> Vec<Vec<[BaseElement; 2]>> {
    vec![
        vec![[ToBin::num(), BaseElement::new(REGISTERS_INDICES[4] as u64)]],
        vec![[ToBin::num(), BaseElement::new(REGISTERS_INDICES[5] as u64)],
             [AND::num(), BaseElement::new(REGISTERS_INDICES[9] as u64)]],
        vec![[ToBin::num(), BaseElement::new(REGISTERS_INDICES[4] as u64)]],
        vec![[NOT::num(), BaseElement::new(0)]],
        vec![[ToBin::num(), BaseElement::new(REGISTERS_INDICES[6] as u64)],
             [AND::num(), BaseElement::new(REGISTERS_INDICES[10] as u64)]],
        vec![[ToBin::num(), BaseElement::new(REGISTERS_INDICES[9] as u64)]],
        vec![[ToBin::num(), BaseElement::new(REGISTERS_INDICES[10] as u64)],
             [XOR::num(), BaseElement::new(REGISTERS_INDICES[9] as u64)]],
    ]
}

// Set temp1 to r8 register
fn calc_temp1(i: usize) -> Vec<Vec<[BaseElement; 2]>> {
    vec![
        vec![[ToBin::num(), BaseElement::new(REGISTERS_INDICES[7] as u64)],
             [SetR10::num(), BaseElement::new(REGISTERS_INDICES[7] as u64)],
             [SetR11::num(), BaseElement::new(REGISTERS_INDICES[8] as u64)]],
        vec![[ToBin::num(), BaseElement::new(REGISTERS_INDICES[8] as u64)],
             [AddStep1::num(), BaseElement::new(0)]],
        vec![[ToBin::num(), BaseElement::new(REGISTERS_INDICES[10] as u64)],
             [AddStep2::num(), BaseElement::new(REGISTERS_INDICES[8] as u64)]],

        vec![[ToBin::num(), BaseElement::new(REGISTERS_INDICES[8] as u64)],
             [SetR10::num(), BaseElement::new(REGISTERS_INDICES[8] as u64)],
             [SetR11::num(), BaseElement::new(REGISTERS_INDICES[9] as u64)]],
        vec![[ToBin::num(), BaseElement::new(REGISTERS_INDICES[9] as u64)],
             [AddStep1::num(), BaseElement::new(0)]],
        vec![[ToBin::num(), BaseElement::new(REGISTERS_INDICES[10] as u64)],
             [AddStep2::num(), BaseElement::new(REGISTERS_INDICES[8] as u64)]],

        vec![[ToBin::num(), BaseElement::new(REGISTERS_INDICES[8] as u64)],
             [SetR10::num(), BaseElement::new(REGISTERS_INDICES[8] as u64)],
             [SetR11Value::num(), BaseElement::new(K[i] as u64)]],
        vec![[SetB::num(), BaseElement::new(K[i] as u64)],
             [AddStep1::num(), BaseElement::new(0)]],
        vec![[ToBin::num(), BaseElement::new(REGISTERS_INDICES[10] as u64)],
             [AddStep2::num(), BaseElement::new(REGISTERS_INDICES[8] as u64)]],

        vec![[ToBin::num(), BaseElement::new(REGISTERS_INDICES[8] as u64)],
             [SetR10::num(), BaseElement::new(REGISTERS_INDICES[8] as u64)],
             [SetR11::num(), BaseElement::new(HARD_MEMORY_INDICES[i % 16] as u64)]],
        vec![[ToBin::num(), BaseElement::new(HARD_MEMORY_INDICES[i % 16] as u64)],
             [AddStep1::num(), BaseElement::new(0)]],
        vec![[ToBin::num(), BaseElement::new(REGISTERS_INDICES[10] as u64)],
             [AddStep2::num(), BaseElement::new(REGISTERS_INDICES[8] as u64)]],
    ]
}

// Set s0 to r9 register
fn calc_s0() -> Vec<Vec<[BaseElement; 2]>> {
    vec![
        vec![[ToBin::num(), BaseElement::new(REGISTERS_INDICES[0] as u64)]],
        vec![[ROR::num(), BaseElement::new(2)],
             [FromBin::num(), BaseElement::new(REGISTERS_INDICES[9] as u64)]],
        vec![[ToBin::num(), BaseElement::new(REGISTERS_INDICES[0] as u64)]],
        vec![[ROR::num(), BaseElement::new(13)],
             [FromBin::num(), BaseElement::new(REGISTERS_INDICES[10] as u64)]],
        vec![[ToBin::num(), BaseElement::new(REGISTERS_INDICES[0] as u64)]],
        vec![[ROR::num(), BaseElement::new(22)]],
        vec![[ToBin::num(), BaseElement::new(REGISTERS_INDICES[10] as u64)],
             [XOR::num(), BaseElement::new(REGISTERS_INDICES[10] as u64)]],
        vec![[ToBin::num(), BaseElement::new(REGISTERS_INDICES[9] as u64)]],
        vec![[ToBin::num(), BaseElement::new(REGISTERS_INDICES[10] as u64)],
             [XOR::num(), BaseElement::new(REGISTERS_INDICES[9] as u64)]],
    ]
}

// Set maj to r10 register
fn calc_maj() -> Vec<Vec<[BaseElement; 2]>> {
    vec![
        vec![[ToBin::num(), BaseElement::new(REGISTERS_INDICES[0] as u64)]],
        vec![[ToBin::num(), BaseElement::new(REGISTERS_INDICES[1] as u64)],
             [AND::num(), BaseElement::new(REGISTERS_INDICES[10] as u64)]],
        vec![[ToBin::num(), BaseElement::new(REGISTERS_INDICES[0] as u64)]],
        vec![[ToBin::num(), BaseElement::new(REGISTERS_INDICES[2] as u64)],
             [AND::num(), BaseElement::new(REGISTERS_INDICES[11] as u64)]],
        vec![[ToBin::num(), BaseElement::new(REGISTERS_INDICES[10] as u64)]],
        vec![[ToBin::num(), BaseElement::new(REGISTERS_INDICES[11] as u64)],
             [XOR::num(), BaseElement::new(REGISTERS_INDICES[10] as u64)]],
        vec![[ToBin::num(), BaseElement::new(REGISTERS_INDICES[1] as u64)]],
        vec![[ToBin::num(), BaseElement::new(REGISTERS_INDICES[2] as u64)],
             [AND::num(), BaseElement::new(REGISTERS_INDICES[11] as u64)]],
        vec![[ToBin::num(), BaseElement::new(REGISTERS_INDICES[11] as u64)]],
        vec![[ToBin::num(), BaseElement::new(REGISTERS_INDICES[10] as u64)],
             [XOR::num(), BaseElement::new(REGISTERS_INDICES[10] as u64)]],
    ]
}

// Set temp2 to r9 register
fn calc_temp2() -> Vec<Vec<[BaseElement; 2]>> {
    vec![
        vec![[ToBin::num(), BaseElement::new(REGISTERS_INDICES[10] as u64)],
             [SetR10::num(), BaseElement::new(REGISTERS_INDICES[10] as u64)],
             [SetR11::num(), BaseElement::new(REGISTERS_INDICES[9] as u64)]],
        vec![[ToBin::num(), BaseElement::new(REGISTERS_INDICES[9] as u64)],
             [AddStep1::num(), BaseElement::new(0)]],
        vec![[ToBin::num(), BaseElement::new(REGISTERS_INDICES[10] as u64)],
             [AddStep2::num(), BaseElement::new(REGISTERS_INDICES[9] as u64)]],
    ]
}

fn update_w_i(i: usize) -> Vec<Vec<[BaseElement; 2]>> {
    /*
        let s0 = (w[i - 15].rotate_right(7)) ^ (w[i - 15].rotate_right(18)) ^ (w[i - 15] >> 3);
        let s1 = (w[i - 2].rotate_right(17)) ^ (w[i - 2].rotate_right(19)) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
    */
    vec![
        vec![[ToBin::num(), BaseElement::new(HARD_MEMORY_INDICES[(i + 1) % 16] as u64)]],
        vec![[ROR::num(), BaseElement::new(7)],
             [FromBin::num(), BaseElement::new(REGISTERS_INDICES[8] as u64)]],
        vec![[ToBin::num(), BaseElement::new(HARD_MEMORY_INDICES[(i + 1) % 16] as u64)]],
        vec![[ROR::num(), BaseElement::new(18)],
             [FromBin::num(), BaseElement::new(REGISTERS_INDICES[9] as u64)]],
        vec![[ToBin::num(), BaseElement::new(HARD_MEMORY_INDICES[(i + 1) % 16] as u64)]],
        vec![[SHR::num(), BaseElement::new(0)]],
        vec![[SHR::num(), BaseElement::new(0)]],
        vec![[SHR::num(), BaseElement::new(0)]],
        vec![[ToBin::num(), BaseElement::new(REGISTERS_INDICES[9] as u64)],
             [XOR::num(), BaseElement::new(REGISTERS_INDICES[9] as u64)]],
        vec![[ToBin::num(), BaseElement::new(REGISTERS_INDICES[9] as u64)]],
        vec![[ToBin::num(), BaseElement::new(REGISTERS_INDICES[8] as u64)],
             [XOR::num(), BaseElement::new(REGISTERS_INDICES[8] as u64)]], // save s0 to r8
        vec![[ToBin::num(), BaseElement::new(HARD_MEMORY_INDICES[(i + 14) % 16] as u64)]],
        vec![[ROR::num(), BaseElement::new(17)],
             [FromBin::num(), BaseElement::new(REGISTERS_INDICES[9] as u64)]],
        vec![[ToBin::num(), BaseElement::new(HARD_MEMORY_INDICES[(i + 14) % 16] as u64)]],
        vec![[ROR::num(), BaseElement::new(19)],
             [FromBin::num(), BaseElement::new(REGISTERS_INDICES[10] as u64)]],
        vec![[ToBin::num(), BaseElement::new(HARD_MEMORY_INDICES[(i + 14) % 16] as u64)]],
        vec![[SHR::num(), BaseElement::new(0)]],
        vec![[SHR::num(), BaseElement::new(0)]],
        vec![[SHR::num(), BaseElement::new(0)]],
        vec![[SHR::num(), BaseElement::new(0)]],
        vec![[SHR::num(), BaseElement::new(0)]],
        vec![[SHR::num(), BaseElement::new(0)]],
        vec![[SHR::num(), BaseElement::new(0)]],
        vec![[SHR::num(), BaseElement::new(0)]],
        vec![[SHR::num(), BaseElement::new(0)]],
        vec![[SHR::num(), BaseElement::new(0)]],
        vec![[ToBin::num(), BaseElement::new(REGISTERS_INDICES[9] as u64)],
             [XOR::num(), BaseElement::new(REGISTERS_INDICES[9] as u64)]],
        vec![[ToBin::num(), BaseElement::new(REGISTERS_INDICES[9] as u64)]],
        vec![[ToBin::num(), BaseElement::new(REGISTERS_INDICES[10] as u64)],
             [XOR::num(), BaseElement::new(REGISTERS_INDICES[9] as u64)]],// save s1 to r9
        
        vec![[ToBin::num(), BaseElement::new(HARD_MEMORY_INDICES[i] as u64)],
             [SetR10::num(), BaseElement::new(HARD_MEMORY_INDICES[i] as u64)],
             [SetR11::num(), BaseElement::new(REGISTERS_INDICES[8] as u64)]],
        vec![[ToBin::num(), BaseElement::new(REGISTERS_INDICES[8] as u64)],
             [AddStep1::num(), BaseElement::new(0)]],
        vec![[ToBin::num(), BaseElement::new(REGISTERS_INDICES[10] as u64)],
             [AddStep2::num(), BaseElement::new(REGISTERS_INDICES[8] as u64)]],

        vec![[ToBin::num(), BaseElement::new(HARD_MEMORY_INDICES[(i + 9) % 16] as u64)],
             [SetR10::num(), BaseElement::new(HARD_MEMORY_INDICES[(i + 9) % 16] as u64)],
             [SetR11::num(), BaseElement::new(REGISTERS_INDICES[8] as u64)]],
        vec![[ToBin::num(), BaseElement::new(REGISTERS_INDICES[8] as u64)],
             [AddStep1::num(), BaseElement::new(0)]],
        vec![[ToBin::num(), BaseElement::new(REGISTERS_INDICES[10] as u64)],
             [AddStep2::num(), BaseElement::new(REGISTERS_INDICES[8] as u64)]],

        vec![[ToBin::num(), BaseElement::new(REGISTERS_INDICES[8] as u64)],
             [SetR10::num(), BaseElement::new(REGISTERS_INDICES[8] as u64)],
             [SetR11::num(), BaseElement::new(REGISTERS_INDICES[9] as u64)]],
        vec![[ToBin::num(), BaseElement::new(REGISTERS_INDICES[9] as u64)],
             [AddStep1::num(), BaseElement::new(0)]],
        vec![[ToBin::num(), BaseElement::new(REGISTERS_INDICES[10] as u64)],
             [AddStep2::num(), BaseElement::new(REGISTERS_INDICES[8] as u64)]],
        
        vec![[ToBin::num(), BaseElement::new(REGISTERS_INDICES[8] as u64)],
             [FromBin::num(), BaseElement::new(HARD_MEMORY_INDICES[i] as u64)]],
    ]
}

fn update_tmp_h() -> Vec<Vec<[BaseElement; 2]>> {
    vec![
        vec![[ToBin::num(), BaseElement::new(REGISTERS_INDICES[6] as u64)],
             [FromBin::num(), BaseElement::new(REGISTERS_INDICES[7] as u64)]],
        vec![[ToBin::num(), BaseElement::new(REGISTERS_INDICES[5] as u64)],
             [FromBin::num(), BaseElement::new(REGISTERS_INDICES[6] as u64)]],
        vec![[ToBin::num(), BaseElement::new(REGISTERS_INDICES[4] as u64)],
             [FromBin::num(), BaseElement::new(REGISTERS_INDICES[5] as u64)]],

        vec![[ToBin::num(), BaseElement::new(REGISTERS_INDICES[3] as u64)],
             [SetR10::num(), BaseElement::new(REGISTERS_INDICES[3] as u64)],
             [SetR11::num(), BaseElement::new(REGISTERS_INDICES[8] as u64)]],
        vec![[ToBin::num(), BaseElement::new(REGISTERS_INDICES[8] as u64)],
             [AddStep1::num(), BaseElement::new(0)]],
        vec![[ToBin::num(), BaseElement::new(REGISTERS_INDICES[10] as u64)],
             [AddStep2::num(), BaseElement::new(REGISTERS_INDICES[4] as u64)]],
        
        vec![[ToBin::num(), BaseElement::new(REGISTERS_INDICES[2] as u64)],
             [FromBin::num(), BaseElement::new(REGISTERS_INDICES[3] as u64)]],
        vec![[ToBin::num(), BaseElement::new(REGISTERS_INDICES[1] as u64)],
             [FromBin::num(), BaseElement::new(REGISTERS_INDICES[2] as u64)]],
        vec![[ToBin::num(), BaseElement::new(REGISTERS_INDICES[0] as u64)],
             [FromBin::num(), BaseElement::new(REGISTERS_INDICES[1] as u64)]],

        vec![[ToBin::num(), BaseElement::new(REGISTERS_INDICES[8] as u64)],
             [SetR10::num(), BaseElement::new(REGISTERS_INDICES[8] as u64)],
             [SetR11::num(), BaseElement::new(REGISTERS_INDICES[9] as u64)]],
        vec![[ToBin::num(), BaseElement::new(REGISTERS_INDICES[9] as u64)],
             [AddStep1::num(), BaseElement::new(0)]],
        vec![[ToBin::num(), BaseElement::new(REGISTERS_INDICES[10] as u64)],
             [AddStep2::num(), BaseElement::new(REGISTERS_INDICES[0] as u64)]],
    ]
}

fn update_h() -> Vec<Vec<[BaseElement; 2]>> {
    vec![
        vec![[ToBin::num(), BaseElement::new(IV_INDICES[0] as u64)],
             [SetR10::num(), BaseElement::new(IV_INDICES[0] as u64)],
             [SetR11::num(), BaseElement::new(REGISTERS_INDICES[0] as u64)]],
        vec![[ToBin::num(), BaseElement::new(REGISTERS_INDICES[0] as u64)],
             [AddStep1::num(), BaseElement::new(0)]],
        vec![[ToBin::num(), BaseElement::new(REGISTERS_INDICES[10] as u64)],
             [AddStep2::num(), BaseElement::new(REGISTERS_INDICES[8] as u64)]],
        vec![[ToBin::num(), BaseElement::new(REGISTERS_INDICES[8] as u64)],
             [FromBin::num(), BaseElement::new(IV_INDICES[0] as u64)]],

        vec![[ToBin::num(), BaseElement::new(IV_INDICES[1] as u64)],
             [SetR10::num(), BaseElement::new(IV_INDICES[1] as u64)],
             [SetR11::num(), BaseElement::new(REGISTERS_INDICES[1] as u64)]],
        vec![[ToBin::num(), BaseElement::new(REGISTERS_INDICES[1] as u64)],
             [AddStep1::num(), BaseElement::new(0)]],
        vec![[ToBin::num(), BaseElement::new(REGISTERS_INDICES[10] as u64)],
             [AddStep2::num(), BaseElement::new(REGISTERS_INDICES[8] as u64)]],
        vec![[ToBin::num(), BaseElement::new(REGISTERS_INDICES[8] as u64)],
             [FromBin::num(), BaseElement::new(IV_INDICES[1] as u64)]],

        vec![[ToBin::num(), BaseElement::new(IV_INDICES[2] as u64)],
             [SetR10::num(), BaseElement::new(IV_INDICES[2] as u64)],
             [SetR11::num(), BaseElement::new(REGISTERS_INDICES[2] as u64)]],
        vec![[ToBin::num(), BaseElement::new(REGISTERS_INDICES[2] as u64)],
             [AddStep1::num(), BaseElement::new(0)]],
        vec![[ToBin::num(), BaseElement::new(REGISTERS_INDICES[10] as u64)],
             [AddStep2::num(), BaseElement::new(REGISTERS_INDICES[8] as u64)]],
        vec![[ToBin::num(), BaseElement::new(REGISTERS_INDICES[8] as u64)],
             [FromBin::num(), BaseElement::new(IV_INDICES[2] as u64)]],

        vec![[ToBin::num(), BaseElement::new(IV_INDICES[3] as u64)],
             [SetR10::num(), BaseElement::new(IV_INDICES[3] as u64)],
             [SetR11::num(), BaseElement::new(REGISTERS_INDICES[3] as u64)]],
        vec![[ToBin::num(), BaseElement::new(REGISTERS_INDICES[3] as u64)],
             [AddStep1::num(), BaseElement::new(0)]],
        vec![[ToBin::num(), BaseElement::new(REGISTERS_INDICES[10] as u64)],
             [AddStep2::num(), BaseElement::new(REGISTERS_INDICES[8] as u64)]],
        vec![[ToBin::num(), BaseElement::new(REGISTERS_INDICES[8] as u64)],
             [FromBin::num(), BaseElement::new(IV_INDICES[3] as u64)]],

        vec![[ToBin::num(), BaseElement::new(IV_INDICES[4] as u64)],
             [SetR10::num(), BaseElement::new(IV_INDICES[4] as u64)],
             [SetR11::num(), BaseElement::new(REGISTERS_INDICES[4] as u64)]],
        vec![[ToBin::num(), BaseElement::new(REGISTERS_INDICES[4] as u64)],
             [AddStep1::num(), BaseElement::new(0)]],
        vec![[ToBin::num(), BaseElement::new(REGISTERS_INDICES[10] as u64)],
             [AddStep2::num(), BaseElement::new(REGISTERS_INDICES[8] as u64)]],
        vec![[ToBin::num(), BaseElement::new(REGISTERS_INDICES[8] as u64)],
             [FromBin::num(), BaseElement::new(IV_INDICES[4] as u64)]],

        vec![[ToBin::num(), BaseElement::new(IV_INDICES[5] as u64)],
             [SetR10::num(), BaseElement::new(IV_INDICES[5] as u64)],
             [SetR11::num(), BaseElement::new(REGISTERS_INDICES[5] as u64)]],
        vec![[ToBin::num(), BaseElement::new(REGISTERS_INDICES[5] as u64)],
             [AddStep1::num(), BaseElement::new(0)]],
        vec![[ToBin::num(), BaseElement::new(REGISTERS_INDICES[10] as u64)],
             [AddStep2::num(), BaseElement::new(REGISTERS_INDICES[8] as u64)]],
        vec![[ToBin::num(), BaseElement::new(REGISTERS_INDICES[8] as u64)],
             [FromBin::num(), BaseElement::new(IV_INDICES[5] as u64)]],

        vec![[ToBin::num(), BaseElement::new(IV_INDICES[6] as u64)],
             [SetR10::num(), BaseElement::new(IV_INDICES[6] as u64)],
             [SetR11::num(), BaseElement::new(REGISTERS_INDICES[6] as u64)]],
        vec![[ToBin::num(), BaseElement::new(REGISTERS_INDICES[6] as u64)],
             [AddStep1::num(), BaseElement::new(0)]],
        vec![[ToBin::num(), BaseElement::new(REGISTERS_INDICES[10] as u64)],
             [AddStep2::num(), BaseElement::new(REGISTERS_INDICES[8] as u64)]],
        vec![[ToBin::num(), BaseElement::new(REGISTERS_INDICES[8] as u64)],
             [FromBin::num(), BaseElement::new(IV_INDICES[6] as u64)]],

        vec![[ToBin::num(), BaseElement::new(IV_INDICES[7] as u64)],
             [SetR10::num(), BaseElement::new(IV_INDICES[7] as u64)],
             [SetR11::num(), BaseElement::new(REGISTERS_INDICES[7] as u64)]],
        vec![[ToBin::num(), BaseElement::new(REGISTERS_INDICES[7] as u64)],
             [AddStep1::num(), BaseElement::new(0)]],
        vec![[ToBin::num(), BaseElement::new(REGISTERS_INDICES[10] as u64)],
             [AddStep2::num(), BaseElement::new(REGISTERS_INDICES[8] as u64)]],
        vec![[ToBin::num(), BaseElement::new(REGISTERS_INDICES[8] as u64)],
             [FromBin::num(), BaseElement::new(IV_INDICES[7] as u64)]],
    ]
}

fn hash_one_round(i: usize) -> Vec<Vec<[BaseElement; 2]>> {
    let mut program = Vec::new();
    program.extend(calc_s1());
    program.extend(calc_ch());
    program.extend(calc_temp1(i));
    program.extend(calc_s0());
    program.extend(calc_maj());
    program.extend(calc_temp2());
    program.extend(update_tmp_h());
    program
}

pub fn get_program() -> Vec<Vec<[BaseElement; 2]>> {
    let mut program = Vec::new();
    program.push(vec![[NOP::num(), BaseElement::new(0)]]);
    // program.extend(sample_program());
    program.extend(create_tmp_iv());
    for i in 0..64 {
        if i >= 16 {
            program.extend(update_w_i(i % 16));
        }
        program.extend(hash_one_round(i));
    }
    program.extend(update_h());
    println!("initial program.len() = {}", program.len());
    let padding_len = program.len().next_power_of_two() - program.len();
    for _ in 0..padding_len {
        program.push(vec![[ResetHardMemory::num(), BaseElement::new(0)]]);
    }
    program
}

