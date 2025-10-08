// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use winterfell::{
    math::ToElements, Air, AirContext, Assertion, EvaluationFrame, TraceInfo
};


use super::{BaseElement, FieldElement, ProofOptions};
use crate::experiment_sha::assertions::{push_input_assertions, push_result_assertions, push_static_assertions, ASSERTIONS_LEN};
use crate::experiment_sha::transitions::{generate_transitions_degrees, setup_add_transitions, setup_and_transitions, setup_bit_info_transitions, setup_check_bit_transitions, setup_copy_memory_transitions, setup_not_transitions, setup_ror_transitions, setup_setb_transitions, setup_shr_transitions, setup_xor_transitions};
use crate::experiment_sha::table_constants::{BIT_REGISTERS_LEN, IV_INDICES, REGISTERS_INDICES, VARIABLES_COUNT};
use crate::experiment_sha::transitions_constants::ROR_TRANSITIONS_SHIFTS;
use crate::experiment_sha::utis::{element_to_u32};
use crate::experiment_sha::vm_program::{get_program, AddStep1, AddStep2, Command, FromBin, ResetHardMemory, SetB, SetR10, SetR11, SetR11Value, ToBin, AND, NOT, PROGRAM_LEN, ROR, SHR, XOR};
use crate::experiment_sha::table_constants::TABLE_WIDTH;

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

    let mut setb2_column = vec![BaseElement::ONE; program.len()];
    for step in 0..program.len() {
        for [command, b1] in program[step].clone() {
            if command == SetB::num() {
                setb2_column[step] = b1;
            }
        }
    }
    columns.push(setb2_column);

    // Для каждой переменной создаем один столбец
    for variable_idx in 0..VARIABLES_COUNT {
        let mut column = vec![BaseElement::ONE; program.len()];
        
        // Анализируем каждый шаг программы
        for step in 0..program.len() {
            for [command, b1] in program[step].clone() {
                let flag = match command {
                    // ToBin команда
                    cmd if cmd == ToBin::num() => {
                        // Для ToBin: копируем все переменные, кроме тех, которые преобразуются в биты
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
                    cmd if cmd == XOR::num() || cmd == AND::num() => {
                        if variable_idx == element_to_u32(b1) as usize {
                            BaseElement::ZERO
                        } else {
                            BaseElement::ONE
                        }
                    },
                    cmd if cmd == AddStep1::num() => {
                        if variable_idx == REGISTERS_INDICES[10] || variable_idx == REGISTERS_INDICES[11] {
                            BaseElement::ZERO
                        } else {
                            BaseElement::ONE
                        }
                    },
                    cmd if cmd == AddStep2::num() => {
                        if variable_idx == REGISTERS_INDICES[10] || variable_idx == REGISTERS_INDICES[11] || variable_idx == element_to_u32(b1) as usize {
                            BaseElement::ZERO
                        } else {
                            BaseElement::ONE
                        }
                    },
                    cmd if cmd == SetR10::num() => {
                        if variable_idx == REGISTERS_INDICES[10] {
                            BaseElement::ZERO
                        } else {
                            BaseElement::ONE
                        }
                    },
                    cmd if cmd == SetR11::num() => {
                        if variable_idx == REGISTERS_INDICES[11] {
                            BaseElement::ZERO
                        } else {
                            BaseElement::ONE
                        }
                    },
                    cmd if cmd == SetR11Value::num() => {
                        if variable_idx == REGISTERS_INDICES[11] {
                            BaseElement::ZERO
                        } else {
                            BaseElement::ONE
                        }
                    },
                    _ => BaseElement::ONE,
                };
                if flag == BaseElement::ZERO {
                    column[step] = flag;
                }
            }
        }
        
        columns.push(column);
    }
    
    // Добавляем флаги для копирования битовых столбцов
    for _ in 0..BIT_REGISTERS_LEN {
        let mut column = vec![BaseElement::ONE; program.len()];
        
        // Анализируем каждый шаг программы
        for step in 0..program.len() {
            for [command, _] in program[step].clone() {
                let flag = match command {
                    cmd if cmd == ToBin::num() => {
                        BaseElement::ZERO
                    },
                    cmd if cmd == FromBin::num() => {
                        BaseElement::ONE
                    },
                    cmd if cmd == XOR::num() => {
                        BaseElement::ONE
                    },
                    cmd if cmd == AND::num() => {
                        BaseElement::ONE
                    },
                    cmd if cmd == NOT::num() => {
                        BaseElement::ZERO
                    },
                    cmd if cmd == ROR::num() => {
                        BaseElement::ZERO
                    },
                    cmd if cmd == SHR::num() => {
                        BaseElement::ZERO
                    },
                    cmd if cmd == AddStep1::num() => {
                        BaseElement::ONE
                    },
                    cmd if cmd == SetB::num() => {
                        BaseElement::ZERO
                    },
                    _ => BaseElement::ONE,
                };
            
                if flag == BaseElement::ZERO {
                    column[step] = flag;
                }
            }
        }
        
        columns.push(column);
    }
    
    // Добавляем битовую информацию для ToBin (разложение в биты)
    for variable_idx in 0..VARIABLES_COUNT {
        let mut bit_info_column = vec![BaseElement::ZERO; program.len()];
        
        // Анализируем каждый шаг программы
        for step in 0..program.len() {
            for [command, b1] in program[step].clone() {
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
                if bit_flag == BaseElement::ONE {
                    bit_info_column[step] = bit_flag;
                }
            }
        }
        
        columns.push(bit_info_column);
    }

    // Добавляем битовую информацию для FromBin (восстановление из битов)
    for variable_idx in 0..VARIABLES_COUNT {
        let mut bit_info_column = vec![BaseElement::ZERO; program.len()];
        
        // Анализируем каждый шаг программы
        for step in 0..program.len() {
            for [command, b1] in program[step].clone() {
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
            
                if bit_flag == BaseElement::ONE {
                    bit_info_column[step] = bit_flag;
                }
            }
        }
        
        columns.push(bit_info_column);
    }
    
    for register_idx in REGISTERS_INDICES {
        // Добавляем флаги для XOR переходов
        let mut xor_column = vec![BaseElement::ZERO; program.len()];
        
        // Анализируем каждый шаг программы
        for step in 0..program.len() {
            for [command, b1] in program[step].clone() {
                let xor_flag = match command {
                    cmd if cmd == XOR::num() && register_idx == element_to_u32(b1) as usize => {
                        // Для XOR: активируем переходы для всех битов B1
                        BaseElement::ONE
                    },
                    _ => BaseElement::ZERO, // Для других команд не выполняем XOR
                };
                if xor_flag == BaseElement::ONE {
                    xor_column[step] = xor_flag;
                }
            }        
        }
        columns.push(xor_column);
    }
    
    for register_idx in REGISTERS_INDICES {
        // Добавляем флаги для AND переходов
        let mut and_column = vec![BaseElement::ZERO; program.len()];
        
        // Анализируем каждый шаг программы
        for step in 0..program.len() {
            for [command, b1] in program[step].clone() {
                let and_flag = match command {
                    cmd if cmd == AND::num() && register_idx == element_to_u32(b1) as usize => {
                        // Для AND: активируем переходы для всех битов B1
                        BaseElement::ONE
                    },
                    _ => BaseElement::ZERO, // Для других команд не выполняем AND
                };
            
                if and_flag == BaseElement::ONE {
                    and_column[step] = and_flag;
                }
            }
        }        
        columns.push(and_column);
    }
    
    // Добавляем флаги для NOT переходов
    let mut not_column = vec![BaseElement::ZERO; program.len()];
    
    // Анализируем каждый шаг программы
    for step in 0..program.len() {
        for [command, b1] in program[step].clone() {
            let not_flag = match command {
                cmd if cmd == NOT::num() => {
                    // Для NOT: активируем переходы для всех битов B1
                    BaseElement::ONE
                },
                _ => BaseElement::ZERO, // Для других команд не выполняем NOT
            };
            if not_flag == BaseElement::ONE {
                not_column[step] = not_flag;
            }
        }
    }        
    columns.push(not_column);
    
    for shift in ROR_TRANSITIONS_SHIFTS {
        // Добавляем флаги для ROR переходов
        let mut ror_column = vec![BaseElement::ZERO; program.len()];
        
        // Анализируем каждый шаг программы
        for step in 0..program.len() {
            for [command, b1] in program[step].clone() {
                let ror_flag = match command {
                    cmd if cmd == ROR::num() && element_to_u32(b1) as usize == shift => {
                        // Для ROR: активируем переходы для всех битов B1
                        BaseElement::ONE
                    },
                    _ => BaseElement::ZERO, // Для других команд не выполняем ROR
                };
            
                if ror_flag == BaseElement::ONE {
                    ror_column[step] = ror_flag;
                }
            }
        }        
        columns.push(ror_column);
    }
    
    // Добавляем флаги для SHR переходов
    let mut shr_column = vec![BaseElement::ZERO; program.len()];
    
    // Анализируем каждый шаг программы
    for step in 0..program.len() {
        for [command, b1] in program[step].clone() {
            let shr_flag = match command {
                cmd if cmd == SHR::num() => {
                    // Для SHR: активируем переходы для всех битов B1
                    BaseElement::ONE
                },
                _ => BaseElement::ZERO, // Для других команд не выполняем SHR
            };
        
            if shr_flag == BaseElement::ONE {
                shr_column[step] = shr_flag;
            }
        }
    }        
    columns.push(shr_column);
    
    let mut add_1_column = vec![BaseElement::ZERO; program.len()];
    for step in 0..program.len() {
        for [command, _] in program[step].clone() {
        
            let add_flag = match command {
                cmd if cmd == AddStep1::num() => {
                    BaseElement::ONE
                },
                _ => BaseElement::ZERO,
            };
            
            if add_flag == BaseElement::ONE {
                add_1_column[step] = add_flag;
            }
        }
    }        
    columns.push(add_1_column);


    for i in REGISTERS_INDICES {
        let mut add_2_column = vec![BaseElement::ZERO; program.len()];
        for step in 0..program.len() {
            for [command, b1] in program[step].clone() {
                let add_flag = match command {
                    cmd if cmd == AddStep2::num() && i == element_to_u32(b1) as usize => {
                        BaseElement::ONE
                    },
                    _ => BaseElement::ZERO,
                };
                
                if add_flag == BaseElement::ONE {
                    add_2_column[step] = add_flag;
                }
            }
        }        
        columns.push(add_2_column);
    }
    
    // Добавляем флаги для SetB2 переходов
    let mut setb2_column = vec![BaseElement::ZERO; program.len()];
    
    // Анализируем каждый шаг программы
    for step in 0..program.len() {
        for [command, b1] in program[step].clone() {
            let setb2_flag = match command {
                cmd if cmd == SetB::num() => {
                    // Для SetB2: активируем переходы для проверки B2
                    BaseElement::ONE
                },
                _ => BaseElement::ZERO, // Для других команд не выполняем SetB2
            };
            
            if setb2_flag == BaseElement::ONE {
                setb2_column[step] = setb2_flag;
            }
        }
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
        setup_not_transitions(result, current, next, periodic_values);
        setup_ror_transitions(result, current, next, periodic_values);
        setup_shr_transitions(result, current, next, periodic_values);
        setup_add_transitions(result, current, next, periodic_values);
        setup_setb_transitions(result, current, next, periodic_values);
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        let mut assertions = Vec::new();

        push_static_assertions(&mut assertions);

        push_input_assertions(self.data.clone(), &mut assertions);

        push_result_assertions(self.result.clone(), &mut assertions, self.trace_length() - 1);

        assertions
    }

    fn get_periodic_column_values(&self) -> Vec<Vec<Self::BaseField>> {

        debug_assert_eq!(get_program().len(), PROGRAM_LEN);
        let mut periodic_columns = Vec::new();
        
        // Добавляем столбцы для команд программы
        let memory_and_bit_columns = generate_periodic_columns();
        periodic_columns.extend(memory_and_bit_columns);

        println!("periodic_columns.len(): {}", periodic_columns.len());

        periodic_columns
    }
}