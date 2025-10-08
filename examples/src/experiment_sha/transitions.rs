use winterfell::TransitionConstraintDegree;

use crate::experiment_sha::transitions_constants::*;
use crate::experiment_sha::table_constants::*;
use crate::experiment_sha::vm_program::AddStep2;
use crate::experiment_sha::vm_program::SetB;
use crate::experiment_sha::vm_program::{Command, FromBin, ToBin, PROGRAM_LEN, XOR, AND, NOT, ROR, SHR, AddStep1};
use crate::utils::{is_binary, are_equal, EvaluationResult};

use super::BaseElement;
use super::FieldElement;


pub fn generate_transitions_degrees() -> Vec<TransitionConstraintDegree> {
    let mut degrees = Vec::new();
    degrees.extend(vec![TransitionConstraintDegree::with_cycles(1, vec![PROGRAM_LEN]); MEMORY_TRANSITIONS_LEN]);
    degrees.extend(vec![TransitionConstraintDegree::with_cycles(1, vec![PROGRAM_LEN]); BIT_MEMORY_TRANSITIONS_LEN]);
    degrees.extend(vec![TransitionConstraintDegree::new(2); CHECK_BIT_TRANSITIONS_LEN]);
    degrees.extend(vec![TransitionConstraintDegree::with_cycles(1, vec![PROGRAM_LEN]); TO_B1_TRANSITIONS_LEN]);
    degrees.extend(vec![TransitionConstraintDegree::with_cycles(1, vec![PROGRAM_LEN]); FROM_BIN_TRANSITIONS_LEN]);
    degrees.extend(vec![TransitionConstraintDegree::with_cycles(2, vec![PROGRAM_LEN]); XOR_TRANSITIONS_LEN]);
    degrees.extend(vec![TransitionConstraintDegree::with_cycles(2, vec![PROGRAM_LEN]); AND_TRANSITIONS_LEN]);
    degrees.extend(vec![TransitionConstraintDegree::with_cycles(1, vec![PROGRAM_LEN]); NOT_TRANSITIONS_LEN]);
    degrees.extend(vec![TransitionConstraintDegree::with_cycles(1, vec![PROGRAM_LEN]); ROR_TRANSITIONS_LEN]);
    degrees.extend(vec![TransitionConstraintDegree::with_cycles(1, vec![PROGRAM_LEN]); SHR_TRANSITIONS_LEN]);

    // ADD_1 transitions
    degrees.extend(vec![TransitionConstraintDegree::with_cycles(1, vec![PROGRAM_LEN]); 3]);
    degrees.extend(vec![TransitionConstraintDegree::with_cycles(2, vec![PROGRAM_LEN]); 1]);

    // ADD_2 transitions
    degrees.extend(vec![TransitionConstraintDegree::with_cycles(1, vec![PROGRAM_LEN]); 1]);
    degrees.extend(vec![TransitionConstraintDegree::with_cycles(2, vec![PROGRAM_LEN]); 1]);
    degrees.extend(vec![TransitionConstraintDegree::with_cycles(1, vec![PROGRAM_LEN]); REGISTERS_COUNT]);
    
    degrees.extend(vec![TransitionConstraintDegree::with_cycles(1, vec![PROGRAM_LEN]); SETB2_TRANSITIONS_LEN]);
    degrees
}

pub fn setup_copy_memory_transitions<E: FieldElement + From<BaseElement>>(transitions: &mut [E], current_frame: &[E], next_frame: &[E], periodic_values: &[E]) {
    // Используем периодические значения как флаги для активации переходов
    let mut periodic_idx = SET_B2_VALUES;
    
    // Копирование обычных переменных
    for i in 0..MEMORY_TRANSITIONS_LEN {
        // Получаем флаг из периодических значений
        let flag = periodic_values[periodic_idx];
        
        // Активируем переход в зависимости от флага
        // Для copy transition проверяем, что значения не изменились
        transitions.agg_constraint(MEMORY_TRANSITIONS_INDICES[i], flag, are_equal(current_frame[i], next_frame[i]));
        
        periodic_idx += 1;
    }
    
    // Копирование битовых столбцов
    for i in 0..BIT_MEMORY_TRANSITIONS_LEN {
        // Получаем флаг из периодических значений
        let flag = periodic_values[periodic_idx];
        
        // Активируем переход в зависимости от флага
        // Для copy transition проверяем, что битовые значения не изменились
        let bit_index = BIT_REGISTERS_START + i;
        transitions.agg_constraint(BIT_MEMORY_TRANSITIONS_INDICES[i], flag, are_equal(current_frame[bit_index], next_frame[bit_index]));
        
        periodic_idx += 1;
    }
}

 // TODO uncomment https://github.com/facebook/winterfell/blob/2f78ee9bf667a561bdfcdfa68668d0f9b18b8315/prover/src/constraints/evaluation_table.rs#L214. 
pub fn setup_check_bit_transitions<E: FieldElement + From<BaseElement>>(transitions: &mut [E], _: &[E], next_frame: &[E]) {
    for i in 0..CHECK_BIT_TRANSITIONS_LEN {
        transitions[CHECK_BIT_TRANSITIONS_INDICES[i]] = is_binary(next_frame[BIT_REGISTERS_START + i]); // TODO Think next or current?
    }
}

pub fn setup_bit_info_transitions<E: FieldElement + From<BaseElement>>(transitions: &mut [E], current_frame: &[E], next_frame: &[E], periodic_values: &[E]) {
    ToBin::eval_transitions(transitions, current_frame, next_frame, periodic_values);
    FromBin::eval_transitions(transitions, current_frame, next_frame, periodic_values);
}

pub fn setup_xor_transitions<E: FieldElement + From<BaseElement>>(transitions: &mut [E], current_frame: &[E], next_frame: &[E], periodic_values: &[E]) {
    XOR::eval_transitions(transitions, current_frame, next_frame, periodic_values)
}

pub fn setup_and_transitions<E: FieldElement + From<BaseElement>>(transitions: &mut [E], current_frame: &[E], next_frame: &[E], periodic_values: &[E]) {
    AND::eval_transitions(transitions, current_frame, next_frame, periodic_values);
}

pub fn setup_not_transitions<E: FieldElement + From<BaseElement>>(transitions: &mut [E], current_frame: &[E], next_frame: &[E], periodic_values: &[E]) {
    NOT::eval_transitions(transitions, current_frame, next_frame, periodic_values);
}

pub fn setup_ror_transitions<E: FieldElement + From<BaseElement>>(transitions: &mut [E], current_frame: &[E], next_frame: &[E], periodic_values: &[E]) {
    ROR::eval_transitions(transitions, current_frame, next_frame, periodic_values);
}

pub fn setup_shr_transitions<E: FieldElement + From<BaseElement>>(transitions: &mut [E], current_frame: &[E], next_frame: &[E], periodic_values: &[E]) {
    SHR::eval_transitions(transitions, current_frame, next_frame, periodic_values);
}

pub fn setup_add_transitions<E: FieldElement + From<BaseElement>>(transitions: &mut [E], current_frame: &[E], next_frame: &[E], periodic_values: &[E]) {
    AddStep1::eval_transitions(transitions, current_frame, next_frame, periodic_values);
    AddStep2::eval_transitions(transitions, current_frame, next_frame, periodic_values);
}

pub fn setup_setb_transitions<E: FieldElement + From<BaseElement>>(transitions: &mut [E], current_frame: &[E], next_frame: &[E], periodic_values: &[E]) {
    SetB::eval_transitions(transitions, current_frame, next_frame, periodic_values);
}
