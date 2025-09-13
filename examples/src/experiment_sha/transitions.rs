use winterfell::TransitionConstraintDegree;

use crate::experiment_sha::table::{BIT_REGISTERS_LEN, BIT_REGISTERS_START, BIT_REGISTERS_SIZE, VARIABLES_COUNT};
use crate::experiment_sha::vm_program::{Command, FromBin, ToBin, ToBin2, PROGRAM_LEN, XOR, AND, OR, NOT, ROR, SHR, ADD, SetB2};
use crate::utils::{is_binary, are_equal, EvaluationResult};

use super::BaseElement;
use super::FieldElement;


// pub const MEMORY_TRANSITIONS_START: usize = 0;
pub const MEMORY_TRANSITIONS_LEN: usize = VARIABLES_COUNT;
pub const MEMORY_TRANSITIONS_INDICES: [usize; MEMORY_TRANSITIONS_LEN] = {
    let mut indices = [0; MEMORY_TRANSITIONS_LEN];
    let mut i = 0;
    while i < MEMORY_TRANSITIONS_LEN {
        indices[i] = i;
        i += 1;
    }
    indices
};

pub const BIT_MEMORY_TRANSITIONS_LEN: usize = BIT_REGISTERS_LEN;
pub const BIT_MEMORY_TRANSITIONS_START: usize = MEMORY_TRANSITIONS_LEN;
pub const BIT_MEMORY_TRANSITIONS_INDICES: [usize; BIT_MEMORY_TRANSITIONS_LEN] = {
    let mut indices = [0; BIT_MEMORY_TRANSITIONS_LEN];
    let mut i = 0;
    while i < BIT_MEMORY_TRANSITIONS_LEN {
        indices[i] = BIT_MEMORY_TRANSITIONS_START + i;
        i += 1;
    }
    indices
};

pub const CHECK_BIT_TRANSITIONS_LEN: usize = BIT_REGISTERS_LEN;
pub const CHECK_BIT_TRANSITIONS_START: usize = BIT_MEMORY_TRANSITIONS_START + BIT_MEMORY_TRANSITIONS_LEN;
pub const CHECK_BIT_TRANSITIONS_INDICES: [usize; CHECK_BIT_TRANSITIONS_LEN] = {
    let mut indices = [0; CHECK_BIT_TRANSITIONS_LEN];
    let mut i = 0;
    while i < CHECK_BIT_TRANSITIONS_LEN {
        indices[i] = CHECK_BIT_TRANSITIONS_START + i;
        i += 1;
    }
    indices
};

// Битовая информация для переменных
pub const TO_B1_TRANSITIONS_LEN: usize = VARIABLES_COUNT;
pub const TO_B1_TRANSITIONS_START: usize = CHECK_BIT_TRANSITIONS_START + CHECK_BIT_TRANSITIONS_LEN;
pub const TO_B1_TRANSITIONS_INDICES: [usize; TO_B1_TRANSITIONS_LEN] = {
    let mut indices = [0; TO_B1_TRANSITIONS_LEN];
    let mut i = 0;
    while i < TO_B1_TRANSITIONS_LEN {
        indices[i] = TO_B1_TRANSITIONS_START + i;
        i += 1;
    }
    indices
};

pub const TO_B2_TRANSITIONS_LEN: usize = VARIABLES_COUNT;
pub const TO_B2_TRANSITIONS_START: usize = TO_B1_TRANSITIONS_START + TO_B1_TRANSITIONS_LEN;
pub const TO_B2_TRANSITIONS_INDICES: [usize; TO_B2_TRANSITIONS_LEN] = {
    let mut indices = [0; TO_B2_TRANSITIONS_LEN];
    let mut i = 0;
    while i < TO_B2_TRANSITIONS_LEN {
        indices[i] = TO_B2_TRANSITIONS_START + i;
        i += 1;
    }
    indices
};

// Битовая информация для переменных
pub const FROM_BIN_TRANSITIONS_LEN: usize = VARIABLES_COUNT;
pub const FROM_BIN_TRANSITIONS_START: usize = TO_B2_TRANSITIONS_START + TO_B2_TRANSITIONS_LEN;
pub const FROM_BIN_TRANSITIONS_INDICES: [usize; FROM_BIN_TRANSITIONS_LEN] = {
    let mut indices = [0; FROM_BIN_TRANSITIONS_LEN];
    let mut i = 0;
    while i < FROM_BIN_TRANSITIONS_LEN {
        indices[i] = FROM_BIN_TRANSITIONS_START + i;
        i += 1;
    }
    indices
};

pub const XOR_TRANSITIONS_LEN: usize = BIT_REGISTERS_SIZE;
pub const XOR_TRANSITIONS_START: usize = FROM_BIN_TRANSITIONS_START + FROM_BIN_TRANSITIONS_LEN;
pub const XOR_TRANSITIONS_INDICES: [usize; XOR_TRANSITIONS_LEN] = {
    let mut indices = [0; XOR_TRANSITIONS_LEN];
    let mut i = 0;
    while i < XOR_TRANSITIONS_LEN {
        indices[i] = XOR_TRANSITIONS_START + i;
        i += 1;
    }
    indices
};

pub const AND_TRANSITIONS_LEN: usize = BIT_REGISTERS_SIZE;
pub const AND_TRANSITIONS_START: usize = XOR_TRANSITIONS_START + XOR_TRANSITIONS_LEN;
pub const AND_TRANSITIONS_INDICES: [usize; AND_TRANSITIONS_LEN] = {
    let mut indices = [0; AND_TRANSITIONS_LEN];
    let mut i = 0;
    while i < AND_TRANSITIONS_LEN {
        indices[i] = AND_TRANSITIONS_START + i;
        i += 1;
    }
    indices
};

pub const OR_TRANSITIONS_LEN: usize = BIT_REGISTERS_SIZE;
pub const OR_TRANSITIONS_START: usize = AND_TRANSITIONS_START + AND_TRANSITIONS_LEN;
pub const OR_TRANSITIONS_INDICES: [usize; OR_TRANSITIONS_LEN] = {
    let mut indices = [0; OR_TRANSITIONS_LEN];
    let mut i = 0;
    while i < OR_TRANSITIONS_LEN {
        indices[i] = OR_TRANSITIONS_START + i;
        i += 1;
    }
    indices
};

pub const NOT_TRANSITIONS_LEN: usize = BIT_REGISTERS_SIZE;
pub const NOT_TRANSITIONS_START: usize = OR_TRANSITIONS_START + OR_TRANSITIONS_LEN;
pub const NOT_TRANSITIONS_INDICES: [usize; NOT_TRANSITIONS_LEN] = {
    let mut indices = [0; NOT_TRANSITIONS_LEN];
    let mut i = 0;
    while i < NOT_TRANSITIONS_LEN {
        indices[i] = NOT_TRANSITIONS_START + i;
        i += 1;
    }
    indices
};

pub const ROR_TRANSITIONS_LEN: usize = BIT_REGISTERS_SIZE;
pub const ROR_TRANSITIONS_START: usize = NOT_TRANSITIONS_START + NOT_TRANSITIONS_LEN;
pub const ROR_TRANSITIONS_INDICES: [usize; ROR_TRANSITIONS_LEN] = {
    let mut indices = [0; ROR_TRANSITIONS_LEN];
    let mut i = 0;
    while i < ROR_TRANSITIONS_LEN {
        indices[i] = ROR_TRANSITIONS_START + i;
        i += 1;
    }
    indices
};

pub const SHR_TRANSITIONS_LEN: usize = BIT_REGISTERS_SIZE;
pub const SHR_TRANSITIONS_START: usize = ROR_TRANSITIONS_START + ROR_TRANSITIONS_LEN;
pub const SHR_TRANSITIONS_INDICES: [usize; SHR_TRANSITIONS_LEN] = {
    let mut indices = [0; SHR_TRANSITIONS_LEN];
    let mut i = 0;
    while i < SHR_TRANSITIONS_LEN {
        indices[i] = SHR_TRANSITIONS_START + i;
        i += 1;
    }
    indices
};

pub const ADD_TRANSITIONS_LEN: usize = BIT_REGISTERS_SIZE;
pub const ADD_TRANSITIONS_START: usize = SHR_TRANSITIONS_START + SHR_TRANSITIONS_LEN;
pub const ADD_TRANSITIONS_INDICES: [usize; ADD_TRANSITIONS_LEN] = {
    let mut indices = [0; ADD_TRANSITIONS_LEN];
    let mut i = 0;
    while i < ADD_TRANSITIONS_LEN {
        indices[i] = ADD_TRANSITIONS_START + i;
        i += 1;
    }
    indices
};

pub const SETB2_TRANSITIONS_LEN: usize = 1;
pub const SETB2_TRANSITIONS_START: usize = ADD_TRANSITIONS_START + ADD_TRANSITIONS_LEN;
pub const SETB2_TRANSITIONS_INDICES: [usize; SETB2_TRANSITIONS_LEN] = {
    let mut indices = [0; SETB2_TRANSITIONS_LEN];
    let mut i = 0;
    while i < SETB2_TRANSITIONS_LEN {
        indices[i] = SETB2_TRANSITIONS_START + i;
        i += 1;
    }
    indices
};

pub fn generate_transitions_degrees() -> Vec<TransitionConstraintDegree> {
    let mut degrees = Vec::new();
    degrees.extend(vec![TransitionConstraintDegree::with_cycles(1, vec![PROGRAM_LEN]); MEMORY_TRANSITIONS_LEN]);
    degrees.extend(vec![TransitionConstraintDegree::with_cycles(1, vec![PROGRAM_LEN]); BIT_MEMORY_TRANSITIONS_LEN]);
    degrees.extend(vec![TransitionConstraintDegree::new(2); CHECK_BIT_TRANSITIONS_LEN]);
    degrees.extend(vec![TransitionConstraintDegree::with_cycles(1, vec![PROGRAM_LEN]); TO_B1_TRANSITIONS_LEN]);
    degrees.extend(vec![TransitionConstraintDegree::with_cycles(1, vec![PROGRAM_LEN]); TO_B2_TRANSITIONS_LEN]);
    degrees.extend(vec![TransitionConstraintDegree::with_cycles(1, vec![PROGRAM_LEN]); FROM_BIN_TRANSITIONS_LEN]);
    degrees.extend(vec![TransitionConstraintDegree::with_cycles(2, vec![PROGRAM_LEN]); XOR_TRANSITIONS_LEN]);
    degrees.extend(vec![TransitionConstraintDegree::with_cycles(2, vec![PROGRAM_LEN]); AND_TRANSITIONS_LEN]);
    degrees.extend(vec![TransitionConstraintDegree::with_cycles(2, vec![PROGRAM_LEN]); OR_TRANSITIONS_LEN]);
    degrees.extend(vec![TransitionConstraintDegree::with_cycles(1, vec![PROGRAM_LEN]); NOT_TRANSITIONS_LEN]);
    degrees.extend(vec![TransitionConstraintDegree::with_cycles(1, vec![PROGRAM_LEN]); ROR_TRANSITIONS_LEN]);
    degrees.extend(vec![TransitionConstraintDegree::with_cycles(1, vec![PROGRAM_LEN]); SHR_TRANSITIONS_LEN]);
    degrees.extend(vec![TransitionConstraintDegree::with_cycles(2, vec![PROGRAM_LEN]); 1]);
    degrees.extend(vec![TransitionConstraintDegree::with_cycles(5, vec![PROGRAM_LEN]); ADD_TRANSITIONS_LEN - 1]);
    degrees.extend(vec![TransitionConstraintDegree::with_cycles(1, vec![PROGRAM_LEN]); SETB2_TRANSITIONS_LEN]);
    degrees
}

pub fn setup_copy_memory_transitions<E: FieldElement + From<BaseElement>>(transitions: &mut [E], current_frame: &[E], next_frame: &[E], periodic_values: &[E]) {
    // Используем периодические значения как флаги для активации переходов
    let mut periodic_idx = 2; // Начинаем с индекса 2 (после command, b1)
    
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
    // Используем периодические значения как флаги для битовой информации
    let mut periodic_idx = 2 + MEMORY_TRANSITIONS_LEN + BIT_MEMORY_TRANSITIONS_LEN; // Начинаем после command, b1, copy_memory_transitions и bit_copy_memory_transitions
    
    // Обрабатываем ToBin bit_info_transitions
    for i in 0..TO_B1_TRANSITIONS_LEN {
        
        // Получаем флаг из периодических значений для ToBin
        let flag = periodic_values[periodic_idx];
        
        // Для ToBin: проверяем, что переменная разложена в биты
        let constraint_value = ToBin::eval_transitions(current_frame, next_frame, i, periodic_values);
        
        transitions.agg_constraint(TO_B1_TRANSITIONS_INDICES[i], flag, constraint_value);
        
        periodic_idx += 1;
    }

    for i in 0..TO_B2_TRANSITIONS_LEN {
        // Проверяем, что индекс не выходит за границы массива
        if periodic_idx >= periodic_values.len() {
            println!("ERROR: periodic_idx {} >= periodic_values.len() {}", periodic_idx, periodic_values.len());
            break;
        }
        
        // Получаем флаг из периодических значений для ToBin2
        let flag = periodic_values[periodic_idx];
        
        // Для ToBin2: проверяем, что переменная разложена в биты
        let constraint_value = ToBin2::eval_transitions(current_frame, next_frame, i, periodic_values);
        
        transitions.agg_constraint(TO_B2_TRANSITIONS_INDICES[i], flag, constraint_value);
        
        periodic_idx += 1;
    }

    // Обрабатываем FromBin bit_info_transitions
    for i in 0..FROM_BIN_TRANSITIONS_LEN {
        // Проверяем, что индекс не выходит за границы массива
        if periodic_idx >= periodic_values.len() {
            println!("ERROR: periodic_idx {} >= periodic_values.len() {}", periodic_idx, periodic_values.len());
            break;
        }
        
        // Получаем флаг из периодических значений для FromBin
        let flag = periodic_values[periodic_idx];
        
        // Для FromBin: проверяем, что переменная восстановлена из битов
        let constraint_value = FromBin::eval_transitions(current_frame, next_frame, i, periodic_values);
        
        transitions.agg_constraint(FROM_BIN_TRANSITIONS_INDICES[i], flag, constraint_value);
        
        periodic_idx += 1;
    }
}

pub fn setup_xor_transitions<E: FieldElement + From<BaseElement>>(transitions: &mut [E], current_frame: &[E], next_frame: &[E], periodic_values: &[E]) {
    // Используем периодические значения как флаги для XOR операций
    let periodic_idx = 2 + MEMORY_TRANSITIONS_LEN + BIT_MEMORY_TRANSITIONS_LEN + TO_B1_TRANSITIONS_LEN + TO_B2_TRANSITIONS_LEN + FROM_BIN_TRANSITIONS_LEN;
    let flag = periodic_values[periodic_idx];
    
    // Обрабатываем XOR transitions
    for i in 0..XOR_TRANSITIONS_LEN {
        // Проверяем, что индекс не выходит за границы массива
        if periodic_idx >= periodic_values.len() {
            println!("ERROR: periodic_idx {} >= periodic_values.len() {}", periodic_idx, periodic_values.len());
            break;
        }
        
        // Для XOR: проверяем, что операция выполнена правильно
        let constraint_value = XOR::eval_transitions(current_frame, next_frame, i, periodic_values);
        transitions.agg_constraint(XOR_TRANSITIONS_INDICES[i], flag, constraint_value);
    }
}

pub fn setup_and_transitions<E: FieldElement + From<BaseElement>>(transitions: &mut [E], current_frame: &[E], next_frame: &[E], periodic_values: &[E]) {
    // Используем периодические значения как флаги для AND операций
    let periodic_idx = 2 + MEMORY_TRANSITIONS_LEN + BIT_MEMORY_TRANSITIONS_LEN + TO_B1_TRANSITIONS_LEN + TO_B2_TRANSITIONS_LEN + FROM_BIN_TRANSITIONS_LEN + 1; // +1 для XOR
    let flag = periodic_values[periodic_idx];
    
    // Обрабатываем AND transitions
    for i in 0..AND_TRANSITIONS_LEN {
        // Проверяем, что индекс не выходит за границы массива
        if periodic_idx >= periodic_values.len() {
            println!("ERROR: periodic_idx {} >= periodic_values.len() {}", periodic_idx, periodic_values.len());
            break;
        }
        
        // Для AND: проверяем, что операция выполнена правильно
        let constraint_value = AND::eval_transitions(current_frame, next_frame, i, periodic_values);
        transitions.agg_constraint(AND_TRANSITIONS_INDICES[i], flag, constraint_value);
    }
}

pub fn setup_or_transitions<E: FieldElement + From<BaseElement>>(transitions: &mut [E], current_frame: &[E], next_frame: &[E], periodic_values: &[E]) {
    // Используем периодические значения как флаги для OR операций
    let periodic_idx = 2 + MEMORY_TRANSITIONS_LEN + BIT_MEMORY_TRANSITIONS_LEN + TO_B1_TRANSITIONS_LEN + TO_B2_TRANSITIONS_LEN + FROM_BIN_TRANSITIONS_LEN + 2; // +2 для XOR и AND
    let flag = periodic_values[periodic_idx];
    
    // Обрабатываем OR transitions
    for i in 0..OR_TRANSITIONS_LEN {
        // Проверяем, что индекс не выходит за границы массива
        if periodic_idx >= periodic_values.len() {
            println!("ERROR: periodic_idx {} >= periodic_values.len() {}", periodic_idx, periodic_values.len());
            break;
        }
        
        // Для OR: проверяем, что операция выполнена правильно
        let constraint_value = OR::eval_transitions(current_frame, next_frame, i, periodic_values);
        transitions.agg_constraint(OR_TRANSITIONS_INDICES[i], flag, constraint_value);
    }
}

pub fn setup_not_transitions<E: FieldElement + From<BaseElement>>(transitions: &mut [E], current_frame: &[E], next_frame: &[E], periodic_values: &[E]) {
    // Используем периодические значения как флаги для NOT операций
    let periodic_idx = 2 + MEMORY_TRANSITIONS_LEN + BIT_MEMORY_TRANSITIONS_LEN + TO_B1_TRANSITIONS_LEN + TO_B2_TRANSITIONS_LEN + FROM_BIN_TRANSITIONS_LEN + 3; // +3 для XOR, AND и OR
    let flag = periodic_values[periodic_idx];
    
    // Обрабатываем NOT transitions
    for i in 0..NOT_TRANSITIONS_LEN {
        // Проверяем, что индекс не выходит за границы массива
        if periodic_idx >= periodic_values.len() {
            println!("ERROR: periodic_idx {} >= periodic_values.len() {}", periodic_idx, periodic_values.len());
            break;
        }
        
        // Для NOT: проверяем, что операция выполнена правильно
        let constraint_value = NOT::eval_transitions(current_frame, next_frame, i, periodic_values);
        transitions.agg_constraint(NOT_TRANSITIONS_INDICES[i], flag, constraint_value);
    }
}

pub fn setup_ror_transitions<E: FieldElement + From<BaseElement>>(transitions: &mut [E], current_frame: &[E], next_frame: &[E], periodic_values: &[E]) {
    // Используем периодические значения как флаги для ROR операций
    let periodic_idx = 2 + MEMORY_TRANSITIONS_LEN + BIT_MEMORY_TRANSITIONS_LEN + TO_B1_TRANSITIONS_LEN + TO_B2_TRANSITIONS_LEN + FROM_BIN_TRANSITIONS_LEN + 4; // +4 для XOR, AND, OR и NOT
    let flag = periodic_values[periodic_idx];
    
    // Обрабатываем ROR transitions
    for i in 0..ROR_TRANSITIONS_LEN {
        // Проверяем, что индекс не выходит за границы массива
        if periodic_idx >= periodic_values.len() {
            println!("ERROR: periodic_idx {} >= periodic_values.len() {}", periodic_idx, periodic_values.len());
            break;
        }
        
        // Для ROR: проверяем, что операция выполнена правильно
        let constraint_value = ROR::eval_transitions(current_frame, next_frame, i, periodic_values);
        transitions.agg_constraint(ROR_TRANSITIONS_INDICES[i], flag, constraint_value);
    }
}

pub fn setup_shr_transitions<E: FieldElement + From<BaseElement>>(transitions: &mut [E], current_frame: &[E], next_frame: &[E], periodic_values: &[E]) {
    // Используем периодические значения как флаги для SHR операций
    let periodic_idx = 2 + MEMORY_TRANSITIONS_LEN + BIT_MEMORY_TRANSITIONS_LEN + TO_B1_TRANSITIONS_LEN + TO_B2_TRANSITIONS_LEN + FROM_BIN_TRANSITIONS_LEN + 5; // +5 для XOR, AND, OR, NOT и ROR
    let flag = periodic_values[periodic_idx];
    
    // Обрабатываем SHR transitions
    for i in 0..SHR_TRANSITIONS_LEN {
        // Проверяем, что индекс не выходит за границы массива
        if periodic_idx >= periodic_values.len() {
            println!("ERROR: periodic_idx {} >= periodic_values.len() {}", periodic_idx, periodic_values.len());
            break;
        }
        
        // Для SHR: проверяем, что операция выполнена правильно
        let constraint_value = SHR::eval_transitions(current_frame, next_frame, i, periodic_values);
        transitions.agg_constraint(SHR_TRANSITIONS_INDICES[i], flag, constraint_value);
    }
}

pub fn setup_add_transitions<E: FieldElement + From<BaseElement>>(transitions: &mut [E], current_frame: &[E], next_frame: &[E], periodic_values: &[E]) {
    // Используем периодические значения как флаги для ADD операций
    let periodic_idx = 2 + MEMORY_TRANSITIONS_LEN + BIT_MEMORY_TRANSITIONS_LEN + TO_B1_TRANSITIONS_LEN + TO_B2_TRANSITIONS_LEN + FROM_BIN_TRANSITIONS_LEN + 6; // +6 для XOR, AND, OR, NOT, ROR и SHR
    let flag = periodic_values[periodic_idx];
    
    // Обрабатываем ADD transitions
    for i in 0..ADD_TRANSITIONS_LEN {
        // Проверяем, что индекс не выходит за границы массива
        if periodic_idx >= periodic_values.len() {
            println!("ERROR: periodic_idx {} >= periodic_values.len() {}", periodic_idx, periodic_values.len());
            break;
        }
        
        // Для ADD: проверяем, что операция выполнена правильно
        let constraint_value = ADD::eval_transitions(current_frame, next_frame, i, periodic_values);
        transitions.agg_constraint(ADD_TRANSITIONS_INDICES[i], flag, constraint_value);
    }
}

pub fn setup_setb2_transitions<E: FieldElement + From<BaseElement>>(transitions: &mut [E], current_frame: &[E], next_frame: &[E], periodic_values: &[E]) {
    // Используем периодические значения как флаги для SetB2 операций
    let periodic_idx = 2 + MEMORY_TRANSITIONS_LEN + BIT_MEMORY_TRANSITIONS_LEN + TO_B1_TRANSITIONS_LEN + TO_B2_TRANSITIONS_LEN + FROM_BIN_TRANSITIONS_LEN + 7; // +7 для XOR, AND, OR, NOT, ROR, SHR и ADD
    let flag = periodic_values[periodic_idx];
    
    // Обрабатываем SetB2 transitions
    for i in 0..SETB2_TRANSITIONS_LEN {
        // Проверяем, что индекс не выходит за границы массива
        if periodic_idx >= periodic_values.len() {
            println!("ERROR: periodic_idx {} >= periodic_values.len() {}", periodic_idx, periodic_values.len());
            break;
        }
        
        // Для SetB2: проверяем, что B2 устанавливается в правильное значение
        let constraint_value = SetB2::eval_transitions(current_frame, next_frame, i, periodic_values);
        transitions.agg_constraint(SETB2_TRANSITIONS_INDICES[i], flag, constraint_value);
    }
}
