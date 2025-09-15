// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use winterfell::{
    math::ToElements, Air, AirContext, Assertion, EvaluationFrame, TraceInfo
};


use super::{BaseElement, FieldElement, ProofOptions};
use crate::experiment_sha::assertions::{push_input_assertions, push_result_assertions, push_static_assertions, ASSERTIONS_LEN};
use crate::experiment_sha::transitions::{generate_transitions_degrees, setup_check_bit_transitions, setup_copy_memory_transitions, setup_bit_info_transitions, setup_xor_transitions, setup_and_transitions, setup_or_transitions, setup_not_transitions, setup_ror_transitions, setup_shr_transitions, setup_add_transitions, setup_setb2_transitions};
use crate::experiment_sha::table::{BIT_REGISTERS_LEN, BIT_REGISTERS_SIZE, IV_INDICES, VARIABLES_COUNT};
use crate::experiment_sha::utis::{element_to_u32, transpose_vec};
use crate::experiment_sha::vm_program::{get_program, Command, FromBin, ResetHardMemory, SetB2, ToBin, ToBin2, ADD, AND, NOT, OR, PROGRAM_LEN, ROR, SHR, XOR};
use crate::experiment_sha::table::TABLE_WIDTH;

// const NUM_ASSERTIONS: usize = 24;

pub struct PublicInputs {
    pub data: Vec<[BaseElement; 16]>,
    pub result: Vec<BaseElement>
}

impl ToElements<BaseElement> for PublicInputs {
    fn to_elements(&self) -> Vec<BaseElement> {
        let mut elements: Vec<BaseElement> = self.data.clone().into_iter().flatten().collect();
        elements.extend(self.result.clone());
        elements
    }
}

// HELPER FUNCTIONS
// ================================================================================================

/// Генерирует периодические столбцы для copy_memory_transitions и битовой информации.
/// Анализирует программу и генерирует соответствующие флаги для каждой переменной.
fn generate_periodic_columns() -> Vec<Vec<BaseElement>> {
    let program = get_program();
    let mut columns = Vec::new();
    
    // Для каждой переменной создаем один столбец
    for variable_idx in 0..VARIABLES_COUNT {
        let mut column = Vec::new();
        
        // Анализируем каждый шаг программы
        for step in 0..program.len() {
            let command = program[step][0];
            let b1 = program[step][1];
            
            let flag = match command {
                // ToBin команда
                cmd if cmd == ToBin::num() => {
                    // Для ToBin: копируем все переменные, кроме тех, которые преобразуются в биты
                    BaseElement::ONE
                },
                // ToBin2 команда
                cmd if cmd == ToBin2::num() => {
                    // Для ToBin2: копируем все переменные, кроме тех, которые преобразуются в биты
                    BaseElement::ONE
                },
                cmd if cmd == FromBin::num() => {
                    // Для FromBin: копируем все переменные, кроме тех, которые восстанавливаются из битов
                    if variable_idx == element_to_u32(b1) as usize {
                        BaseElement::ZERO // Эти переменные изменяются (восстанавливаются из битов)
                    } else {
                        BaseElement::ONE // Остальные переменные копируются
                    }
                },
                cmd if cmd == ResetHardMemory::num() => {
                    if IV_INDICES.contains(&variable_idx) {
                        BaseElement::ONE
                    } else {
                        BaseElement::ZERO
                    }
                },
                _ => BaseElement::ONE,
            };
            
            column.push(flag);
        }
        
        columns.push(column);
    }
    
    // Добавляем флаги для копирования битовых столбцов
    for bit_idx in 0..BIT_REGISTERS_LEN {
        let mut column = Vec::new();
        
        // Анализируем каждый шаг программы
        for step in 0..program.len() {
            let command = program[step][0];
            
            let flag = match command {
                // ToBin команда
                cmd if cmd == ToBin::num() => {
                    // Для ToBin: копируем все битовые столбцы, кроме B1
                    if bit_idx < BIT_REGISTERS_SIZE {
                        BaseElement::ZERO // B1 изменяется (записываются биты)
                    } else {
                        BaseElement::ONE // B2 копируется
                    }
                },
                // ToBin2 команда
                cmd if cmd == ToBin2::num() => {
                    // Для ToBin2: копируем все битовые столбцы, кроме B2
                    if bit_idx >= BIT_REGISTERS_SIZE {
                        BaseElement::ZERO // B2 изменяется (записываются биты)
                    } else {
                        BaseElement::ONE // B1 копируется
                    }
                },
                cmd if cmd == FromBin::num() => {
                    BaseElement::ONE
                },
                cmd if cmd == XOR::num() => {
                    // Для XOR: B1 изменяется (результат XOR), B2 копируется
                    if bit_idx < BIT_REGISTERS_SIZE {
                        BaseElement::ZERO // B1 изменяется (результат XOR)
                    } else {
                        BaseElement::ONE // B2 копируется
                    }
                },
                cmd if cmd == AND::num() => {
                    // Для AND: B1 изменяется (результат AND), B2 копируется
                    if bit_idx < BIT_REGISTERS_SIZE {
                        BaseElement::ZERO // B1 изменяется (результат AND)
                    } else {
                        BaseElement::ONE // B2 копируется
                    }
                },
                cmd if cmd == OR::num() => {
                    // Для OR: B1 изменяется (результат OR), B2 копируется
                    if bit_idx < BIT_REGISTERS_SIZE {
                        BaseElement::ZERO // B1 изменяется (результат OR)
                    } else {
                        BaseElement::ONE // B2 копируется
                    }
                },
                cmd if cmd == NOT::num() => {
                    // Для NOT: B1 изменяется (результат NOT), B2 копируется
                    if bit_idx < BIT_REGISTERS_SIZE {
                        BaseElement::ZERO // B1 изменяется (результат NOT)
                    } else {
                        BaseElement::ONE // B2 копируется
                    }
                },
                cmd if cmd == ROR::num() => {
                    // Для ROR: B1 изменяется (результат ROR), B2 копируется
                    if bit_idx < BIT_REGISTERS_SIZE {
                        BaseElement::ZERO // B1 изменяется (результат ROR)
                    } else {
                        BaseElement::ONE // B2 копируется
                    }
                },
                cmd if cmd == SHR::num() => {
                    // Для SHR: B1 изменяется (результат SHR), B2 копируется
                    if bit_idx < BIT_REGISTERS_SIZE {
                        BaseElement::ZERO // B1 изменяется (результат SHR)
                    } else {
                        BaseElement::ONE // B2 копируется
                    }
                },
                cmd if cmd == ADD::num() => {
                    // Для ADD: B1 изменяется (результат ADD), B2 копируется
                    if bit_idx < BIT_REGISTERS_SIZE {
                        BaseElement::ZERO // B1 изменяется (результат ADD)
                    } else {
                        BaseElement::ONE // B2 копируется
                    }
                },
                cmd if cmd == SetB2::num() => {
                    // Для SetB2: B1 копируется, B2 изменяется (устанавливается новое значение)
                    if bit_idx < BIT_REGISTERS_SIZE {
                        BaseElement::ONE // B1 копируется
                    } else {
                        BaseElement::ZERO // B2 изменяется (результат SetB2)
                    }
                },
                _ => BaseElement::ONE, // Для других команд копируем все битовые столбцы
            };
            
            column.push(flag);
        }
        
        columns.push(column);
    }
    
    // Добавляем битовую информацию для ToBin (разложение в биты)
    for variable_idx in 0..VARIABLES_COUNT {
        let mut bit_info_column = Vec::new();
        
        // Анализируем каждый шаг программы
        for step in 0..program.len() {
            let command = program[step][0];
            let b1 = program[step][1];
            
            let bit_flag = match command {
                // ToBin команда
                cmd if cmd == ToBin::num() => {
                    // Для ToBin: переменная b1 будет разложена в биты
                    if variable_idx == element_to_u32(b1) as usize {
                        BaseElement::ONE // Эта переменная будет разложена в биты
                    } else {
                        BaseElement::ZERO // Эта переменная не будет разложена в биты
                    }
                },
                _ => BaseElement::ZERO, // Для других команд не разлагаем в биты
            };
            
            bit_info_column.push(bit_flag);
        }
        
        columns.push(bit_info_column);
    }

    // Добавляем битовую информацию для ToBin (разложение в биты)
    for variable_idx in 0..VARIABLES_COUNT {
        let mut bit_info_column = Vec::new();
        
        // Анализируем каждый шаг программы
        for step in 0..program.len() {
            let command = program[step][0];
            let b1 = program[step][1];
            
            let bit_flag = match command {
                // ToBin команда
                cmd if cmd == ToBin2::num() => {
                    // Для ToBin: переменная b1 будет разложена в биты
                    if variable_idx == element_to_u32(b1) as usize {
                        BaseElement::ONE // Эта переменная будет разложена в биты
                    } else {
                        BaseElement::ZERO // Эта переменная не будет разложена в биты
                    }
                },
                _ => BaseElement::ZERO, // Для других команд не разлагаем в биты
            };
            
            bit_info_column.push(bit_flag);
        }
        
        columns.push(bit_info_column);
    }

    // Добавляем битовую информацию для FromBin (восстановление из битов)
    for variable_idx in 0..VARIABLES_COUNT {
        let mut bit_info_column = Vec::new();
        
        // Анализируем каждый шаг программы
        for step in 0..program.len() {
            let command = program[step][0];
            let b1 = program[step][1];
            
            let bit_flag = match command {
                // FromBin команда
                cmd if cmd == FromBin::num() => {
                    // Для FromBin: переменная b1 будет восстановлена из битов
                    if variable_idx == element_to_u32(b1) as usize {
                        BaseElement::ONE // Эта переменная будет восстановлена из битов
                    } else {
                        BaseElement::ZERO // Эта переменная не будет восстановлена из битов
                    }
                },
                _ => BaseElement::ZERO, // Для других команд не восстанавливаем из битов
            };
            
            bit_info_column.push(bit_flag);
        }
        
        columns.push(bit_info_column);
    }
    
    // Добавляем флаги для XOR переходов
    let mut xor_column = Vec::new();
    
    // Анализируем каждый шаг программы
    for step in 0..program.len() {
        let command = program[step][0];
        
        let xor_flag = match command {
            cmd if cmd == XOR::num() => {
                // Для XOR: активируем переходы для всех битов B1
                BaseElement::ONE
            },
            _ => BaseElement::ZERO, // Для других команд не выполняем XOR
        };
        
        xor_column.push(xor_flag);
    }        
    columns.push(xor_column);
    
    // Добавляем флаги для AND переходов
    let mut and_column = Vec::new();
    
    // Анализируем каждый шаг программы
    for step in 0..program.len() {
        let command = program[step][0];
        
        let and_flag = match command {
            cmd if cmd == AND::num() => {
                // Для AND: активируем переходы для всех битов B1
                BaseElement::ONE
            },
            _ => BaseElement::ZERO, // Для других команд не выполняем AND
        };
        
        and_column.push(and_flag);
    }        
    columns.push(and_column);
    
    // Добавляем флаги для OR переходов
    let mut or_column = Vec::new();
    
    // Анализируем каждый шаг программы
    for step in 0..program.len() {
        let command = program[step][0];
        
        let or_flag = match command {
            cmd if cmd == OR::num() => {
                // Для OR: активируем переходы для всех битов B1
                BaseElement::ONE
            },
            _ => BaseElement::ZERO, // Для других команд не выполняем OR
        };
        
        or_column.push(or_flag);
    }        
    columns.push(or_column);
    
    // Добавляем флаги для NOT переходов
    let mut not_column = Vec::new();
    
    // Анализируем каждый шаг программы
    for step in 0..program.len() {
        let command = program[step][0];
        
        let not_flag = match command {
            cmd if cmd == NOT::num() => {
                // Для NOT: активируем переходы для всех битов B1
                BaseElement::ONE
            },
            _ => BaseElement::ZERO, // Для других команд не выполняем NOT
        };
        
        not_column.push(not_flag);
    }        
    columns.push(not_column);
    
    // Добавляем флаги для ROR переходов
    let mut ror_column = Vec::new();
    
    // Анализируем каждый шаг программы
    for step in 0..program.len() {
        let command = program[step][0];
        
        let ror_flag = match command {
            cmd if cmd == ROR::num() => {
                // Для ROR: активируем переходы для всех битов B1
                BaseElement::ONE
            },
            _ => BaseElement::ZERO, // Для других команд не выполняем ROR
        };
        
        ror_column.push(ror_flag);
    }        
    columns.push(ror_column);
    
    // Добавляем флаги для SHR переходов
    let mut shr_column = Vec::new();
    
    // Анализируем каждый шаг программы
    for step in 0..program.len() {
        let command = program[step][0];
        
        let shr_flag = match command {
            cmd if cmd == SHR::num() => {
                // Для SHR: активируем переходы для всех битов B1
                BaseElement::ONE
            },
            _ => BaseElement::ZERO, // Для других команд не выполняем SHR
        };
        
        shr_column.push(shr_flag);
    }        
    columns.push(shr_column);
    
    // Добавляем флаги для ADD переходов
    let mut add_column = Vec::new();
    
    // Анализируем каждый шаг программы
    for step in 0..program.len() {
        let command = program[step][0];
        
        let add_flag = match command {
            cmd if cmd == ADD::num() => {
                // Для ADD: активируем переходы для всех битов B1
                BaseElement::ONE
            },
            _ => BaseElement::ZERO, // Для других команд не выполняем ADD
        };
        
        add_column.push(add_flag);
    }        
    columns.push(add_column);
    
    // Добавляем флаги для SetB2 переходов
    let mut setb2_column = Vec::new();
    
    // Анализируем каждый шаг программы
    for step in 0..program.len() {
        let command = program[step][0];
        
        let setb2_flag = match command {
            cmd if cmd == SetB2::num() => {
                // Для SetB2: активируем переходы для проверки B2
                BaseElement::ONE
            },
            _ => BaseElement::ZERO, // Для других команд не выполняем SetB2
        };
        
        setb2_column.push(setb2_flag);
    }        
    columns.push(setb2_column);
    
    columns
}

// EXPERIMENT SHA AIR
// ================================================================================================

pub struct ExperimentShaAir {
    context: AirContext<BaseElement>,
    data: Vec<[BaseElement; 16]>,
    result: Vec<BaseElement>,
}

impl Air for ExperimentShaAir {
    type BaseField = BaseElement;
    type PublicInputs = PublicInputs;

    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------
    fn new(trace_info: TraceInfo, pub_inputs: PublicInputs, options: ProofOptions) -> Self {
        let degrees = generate_transitions_degrees();
        assert_eq!(TABLE_WIDTH, trace_info.width());
        ExperimentShaAir {
            context: AirContext::new(trace_info, degrees, ASSERTIONS_LEN, options),
            data: pub_inputs.data,
            result: pub_inputs.result,
        }
    }

    fn context(&self) -> &AirContext<Self::BaseField> {
        &self.context
    }

    fn evaluate_transition<E: FieldElement + From<Self::BaseField>>(
        &self,
        frame: &EvaluationFrame<E>,
        periodic_values: &[E],
        result: &mut [E],
    ) {
        let current = frame.current();
        let next = frame.next();
        setup_copy_memory_transitions(result, current, next, periodic_values);
        setup_check_bit_transitions(result, current, next);
        setup_bit_info_transitions(result, current, next, periodic_values);
        setup_xor_transitions(result, current, next, periodic_values);
        setup_and_transitions(result, current, next, periodic_values);
        setup_or_transitions(result, current, next, periodic_values);
        setup_not_transitions(result, current, next, periodic_values);
        setup_ror_transitions(result, current, next, periodic_values);
        setup_shr_transitions(result, current, next, periodic_values);
        setup_add_transitions(result, current, next, periodic_values);
        setup_setb2_transitions(result, current, next, periodic_values);
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        let mut assertions = Vec::new();

        push_static_assertions(&mut assertions);

        // ata: {:?}", self.data);
        push_input_assertions(self.data.clone(), &mut assertions);

        push_result_assertions(self.result.clone(), &mut assertions, self.trace_length() - 1);

        assertions
    }

    fn get_periodic_column_values(&self) -> Vec<Vec<Self::BaseField>> {

        debug_assert_eq!(get_program().len(), PROGRAM_LEN);
        let mut periodic_columns = Vec::new();
        
        // Добавляем столбцы программы (команда, b1)
        let program_result = transpose_vec(get_program());
        periodic_columns.extend(program_result.into_iter());
        
        // Добавляем столбцы для команд программы
        let memory_and_bit_columns = generate_periodic_columns();
        periodic_columns.extend(memory_and_bit_columns);

        println!("periodic_columns.len(): {}", periodic_columns.len());

        periodic_columns
    }
}