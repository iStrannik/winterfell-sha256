use crate::experiment_sha::table::{add_bit_registers, and_bit_registers, not_bit_registers, or_bit_registers, ror_bit_registers, set_from_bit_register, set_to_bit_register, set_to_bit_register_b2, shr_bit_registers, xor_bit_registers, B1, B2, HARD_MEMORY_INDICES, IV_INDICES, REGISTERS_INDICES};

use super::{BaseElement, FieldElement};

pub trait Command {
    fn num() -> BaseElement;
    fn eval_transitions<E: FieldElement + From<BaseElement>>(current_frame: &[E], next_frame: &[E], idx: usize, periodic_values: &[E]) -> E;
    fn prove(state: &mut [BaseElement], b1: usize);
}

pub struct ToBin;

impl Command for ToBin {
    fn num() -> BaseElement {
        BaseElement::new(0)
    }
    fn eval_transitions<E: FieldElement + From<BaseElement>>(current_frame: &[E], next_frame: &[E], idx: usize, _: &[E]) -> E {
        let two = E::from(BaseElement::new(2));
        let mut p = E::from(BaseElement::new(1));
        let mut in_register = E::from(BaseElement::new(0));
        for i in B1 {
            in_register += next_frame[i] * p;
            p = two * p;
        }
        in_register - current_frame[idx]
    }
    
    fn prove(state: &mut [BaseElement], b1: usize) {
        set_to_bit_register(state, state[b1], B1);
    }
}

pub struct ToBin2;

impl Command for ToBin2 {
    fn num() -> BaseElement {
        BaseElement::new(2)
    }
    fn eval_transitions<E: FieldElement + From<BaseElement>>(current_frame: &[E], next_frame: &[E], idx: usize, _: &[E]) -> E {
        let two = E::from(BaseElement::new(2));
        let mut p = E::from(BaseElement::new(1));
        let mut in_register = E::from(BaseElement::new(0));
        for i in B2 {
            in_register += next_frame[i] * p;
            p = two * p;
        }
        in_register - current_frame[idx]
    }
    
    fn prove(state: &mut [BaseElement], b1: usize) {
        set_to_bit_register(state, state[b1], B2);
    }
}

pub struct FromBin;

impl Command for FromBin {
    fn num() -> BaseElement {
        BaseElement::new(1)
    }
    fn eval_transitions<E: FieldElement + From<BaseElement>>(current_frame: &[E], next_frame: &[E], idx: usize, _: &[E]) -> E {
        let two = E::from(BaseElement::new(2));
        let mut p = E::from(BaseElement::new(1));
        let mut in_register = E::from(BaseElement::new(0));
        for i in B1 {
            in_register += current_frame[i] * p;
            p = two * p;
        }
        in_register - next_frame[idx]
    }
    
    fn prove(state: &mut [BaseElement], b1: usize) {
        set_from_bit_register(state, b1, B1);
    }
}

pub struct XOR;

impl Command for XOR {
    fn num() -> BaseElement {
        BaseElement::new(3)
    }
    
    fn eval_transitions<E: FieldElement + From<BaseElement>>(current_frame: &[E], next_frame: &[E], idx: usize, _: &[E]) -> E {
        // Проверяем, что XOR выполнен правильно для бита idx в B1
        // next_frame[B1[idx]] должно быть равно current_frame[B1[idx]] XOR current_frame[B2[idx]]
        let b1_current = current_frame[B1[idx]];
        let b2_current = current_frame[B2[idx]];
        let b1_next = next_frame[B1[idx]];
        
        // XOR для бинарных значений: a XOR b = a + b - 2*a*b
        let xor_result = b1_current + b2_current - E::from(BaseElement::new(2)) * b1_current * b2_current;
        
        b1_next - xor_result
    }
    
    fn prove(state: &mut [BaseElement], _: usize) {
        // Выполняем XOR между B1 и B2, результат сохраняем в B1
        xor_bit_registers(state);
    }
}

pub struct AND;

impl Command for AND {
    fn num() -> BaseElement {
        BaseElement::new(4)
    }
    
    fn eval_transitions<E: FieldElement + From<BaseElement>>(current_frame: &[E], next_frame: &[E], idx: usize, _: &[E]) -> E {
        // Проверяем, что AND выполнен правильно для бита idx в B1
        // next_frame[B1[idx]] должно быть равно current_frame[B1[idx]] AND current_frame[B2[idx]]
        let b1_current = current_frame[B1[idx]];
        let b2_current = current_frame[B2[idx]];
        let b1_next = next_frame[B1[idx]];
        
        // AND для бинарных значений: a AND b = a * b
        let and_result = b1_current * b2_current;
        
        b1_next - and_result
    }
    
    fn prove(state: &mut [BaseElement], _: usize) {
        // Выполняем AND между B1 и B2, результат сохраняем в B1
        and_bit_registers(state);
    }
}

pub struct OR;

impl Command for OR {
    fn num() -> BaseElement {
        BaseElement::new(5)
    }
    
    fn eval_transitions<E: FieldElement + From<BaseElement>>(current_frame: &[E], next_frame: &[E], idx: usize, _: &[E]) -> E {
        // Проверяем, что OR выполнен правильно для бита idx в B1
        // next_frame[B1[idx]] должно быть равно current_frame[B1[idx]] OR current_frame[B2[idx]]
        let b1_current = current_frame[B1[idx]];
        let b2_current = current_frame[B2[idx]];
        let b1_next = next_frame[B1[idx]];
        
        // OR для бинарных значений: a OR b = a + b - a*b
        let or_result = b1_current + b2_current - b1_current * b2_current;
        
        b1_next - or_result
    }
    
    fn prove(state: &mut [BaseElement], _: usize) {
        // Выполняем OR между B1 и B2, результат сохраняем в B1
        or_bit_registers(state);
    }
}

pub struct NOT;

impl Command for NOT {
    fn num() -> BaseElement {
        BaseElement::new(6)
    }
    
    fn eval_transitions<E: FieldElement + From<BaseElement>>(current_frame: &[E], next_frame: &[E], idx: usize, _: &[E]) -> E {
        // Проверяем, что NOT выполнен правильно для бита idx в B1
        // next_frame[B1[idx]] должно быть равно NOT current_frame[B1[idx]]
        let b1_current = current_frame[B1[idx]];
        let b1_next = next_frame[B1[idx]];
        
        // NOT для бинарных значений: NOT a = 1 - a
        let not_result = E::from(BaseElement::new(1)) - b1_current;
        
        b1_next - not_result
    }
    
    fn prove(state: &mut [BaseElement], _: usize) {
        // Выполняем NOT для B1, результат сохраняем в B1
        not_bit_registers(state);
    }
}

pub struct ROR;

impl Command for ROR {
    fn num() -> BaseElement {
        BaseElement::new(7)
    }
    
    fn eval_transitions<E: FieldElement + From<BaseElement>>(current_frame: &[E], next_frame: &[E], idx: usize, _: &[E]) -> E {
        // Проверяем, что ROR выполнен правильно для бита idx в B1
        // next_frame[B1[idx]] должно быть равно current_frame[B1[(idx + 1) % 32]]
        // кроме случая idx = 31, где next_frame[B1[31]] = current_frame[B1[0]]
        let b1_next = next_frame[B1[idx]];
        
        // Определяем, откуда должен прийти бит после циклического сдвига вправо
        let source_idx = if idx == 31 {
            0 // Старший бит получает значение младшего бита
        } else {
            idx + 1 // Остальные биты сдвигаются вправо
        };
        
        let expected_value = current_frame[B1[source_idx]];
        
        b1_next - expected_value
    }
    
    fn prove(state: &mut [BaseElement], _: usize) {
        // Выполняем циклический сдвиг вправо для B1, результат сохраняем в B1
        ror_bit_registers(state);
    }
}

pub struct SHR;

impl Command for SHR {
    fn num() -> BaseElement {
        BaseElement::new(8)
    }
    
    fn eval_transitions<E: FieldElement + From<BaseElement>>(current_frame: &[E], next_frame: &[E], idx: usize, _: &[E]) -> E {
        // Проверяем, что SHR выполнен правильно для бита idx в B1
        // next_frame[B1[idx]] должно быть равно current_frame[B1[idx + 1]] для idx < 31
        // next_frame[B1[31]] должно быть равно 0 (старший бит становится 0)
        let b1_next = next_frame[B1[idx]];
        
        // Определяем ожидаемое значение после сдвига вправо
        let expected_value = if idx == 31 {
            E::from(BaseElement::new(0)) // Старший бит становится 0
        } else {
            current_frame[B1[idx + 1]] // Остальные биты сдвигаются вправо
        };
        
        b1_next - expected_value
    }
    
    fn prove(state: &mut [BaseElement], _: usize) {
        // Выполняем сдвиг вправо (деление на 2) для B1, результат сохраняем в B1
        shr_bit_registers(state);
    }
}

pub struct ADD;

impl Command for ADD {
    fn num() -> BaseElement {
        BaseElement::new(9)
    }
    
    fn eval_transitions<E: FieldElement + From<BaseElement>>(current_frame: &[E], next_frame: &[E], idx: usize, _: &[E]) -> E {
        // Проверяем, что ADD выполнен правильно для бита idx в B1
        // next_frame[B1[idx]] должно быть равно результату сложения B1[idx] + B2[idx] + carry
        let b1_current = current_frame[B1[idx]];
        let b2_current = current_frame[B2[idx]];
        let b1_next = next_frame[B1[idx]];
 
        if idx == 0 {
            b1_next - (b1_current + b2_current - E::from(BaseElement::new(2)) * b1_current * b2_current)
        } else {
            let b1_lower = current_frame[B1[idx - 1]];
            let b2_lower = current_frame[B2[idx - 1]];
            let b1_next_lower = next_frame[B1[idx - 1]];
            let carry_bit = b1_lower * b2_lower + (E::ONE - b1_lower) * b2_lower * (E::ONE - b1_next_lower) + b1_lower * (E::ONE - b2_lower) * (E::ONE - b1_next_lower);
            let mut sum_result = b1_current + b2_current - E::from(BaseElement::new(2)) * b1_current * b2_current;
            sum_result = sum_result + carry_bit - E::from(BaseElement::new(2)) * sum_result * carry_bit;
            b1_next - sum_result
        }
    }
    
    fn prove(state: &mut [BaseElement], _: usize) {
        // Выполняем сложение B1 + B2 по модулю 2^32, результат сохраняем в B1
        add_bit_registers(state);
    }
}

pub struct SetB2;

impl Command for SetB2 {
    fn num() -> BaseElement {
        BaseElement::new(10)
    }
    
    fn eval_transitions<E: FieldElement + From<BaseElement>>(_: &[E], next_frame: &[E], _: usize, periodic_values: &[E]) -> E {
        let two = E::from(BaseElement::new(2));
        let mut p = E::from(BaseElement::new(1));
        let mut in_register = E::from(BaseElement::new(0));
        for i in B2 {
            in_register += next_frame[i] * p;
            p = two * p;
        }
        in_register - periodic_values[1]
    }
    
    fn prove(state: &mut [BaseElement], value: usize) {
        // Получаем значение из параметра value и устанавливаем его в B2
        let base_element_value = BaseElement::new(value as u128);
        set_to_bit_register_b2(state, base_element_value);
    }
}

pub struct NOP;

impl Command for NOP {
    fn num() -> BaseElement {
        BaseElement::new(11)
    }
    
    fn eval_transitions<E: FieldElement + From<BaseElement>>(_: &[E], _: &[E], _: usize, _: &[E]) -> E {
        // NOP ничего не делает - просто проверяем, что все ячейки остались неизменными
        E::ZERO
    }
    
    fn prove(_: &mut [BaseElement], _: usize) {
        // NOP ничего не делает - состояние остается неизменным
    }
}

pub struct ResetHardMemory;

impl Command for ResetHardMemory {
    fn num() -> BaseElement {
        BaseElement::new(12)
    }
    
    fn eval_transitions<E: FieldElement + From<BaseElement>>(_: &[E], _: &[E], _: usize, _: &[E]) -> E {
        // ResetHardMemory отключает ограничения копирования для hard memory
        // Не накладывает никаких ограничений - hard memory может изменяться свободно
        E::ZERO
    }
    
    fn prove(_: &mut [BaseElement], _: usize) {
        // ResetHardMemory отключает ограничения копирования для hard memory
        // Не изменяет состояние - hard memory может изменяться свободно
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

pub const PROGRAM_LEN: usize = 16384;

fn sample_program() -> Vec<[BaseElement; 2]> {
    vec![
        [ToBin::num(), BaseElement::new(0)],
        [ToBin2::num(), BaseElement::new(1)],
        [XOR::num(), BaseElement::new(0)],
        [AND::num(), BaseElement::new(0)],
        [OR::num(), BaseElement::new(0)],
        [NOT::num(), BaseElement::new(0)],
        [ROR::num(), BaseElement::new(0)],
        [SHR::num(), BaseElement::new(0)],
        [ADD::num(), BaseElement::new(0)],
        [SetB2::num(), BaseElement::new(155)],
        [NOP::num(), BaseElement::new(0)],
        [ResetHardMemory::num(), BaseElement::new(0)],
    ]
}

fn create_tmp_iv() -> Vec<[BaseElement; 2]> {
    vec![
        [ToBin::num(), BaseElement::new(IV_INDICES[0] as u128)],
        [FromBin::num(), BaseElement::new(REGISTERS_INDICES[0] as u128)], // tmp_h[0]
        [ToBin::num(), BaseElement::new(IV_INDICES[1] as u128)],
        [FromBin::num(), BaseElement::new(REGISTERS_INDICES[1] as u128)], // tmp_h[1]
        [ToBin::num(), BaseElement::new(IV_INDICES[2] as u128)],
        [FromBin::num(), BaseElement::new(REGISTERS_INDICES[2] as u128)], // tmp_h[2]
        [ToBin::num(), BaseElement::new(IV_INDICES[3] as u128)],
        [FromBin::num(), BaseElement::new(REGISTERS_INDICES[3] as u128)], // tmp_h[3]
        [ToBin::num(), BaseElement::new(IV_INDICES[4] as u128)],
        [FromBin::num(), BaseElement::new(REGISTERS_INDICES[4] as u128)], // tmp_h[4]
        [ToBin::num(), BaseElement::new(IV_INDICES[5] as u128)],
        [FromBin::num(), BaseElement::new(REGISTERS_INDICES[5] as u128)], // tmp_h[5]
        [ToBin::num(), BaseElement::new(IV_INDICES[6] as u128)],
        [FromBin::num(), BaseElement::new(REGISTERS_INDICES[6] as u128)], // tmp_h[6]
        [ToBin::num(), BaseElement::new(IV_INDICES[7] as u128)],
        [FromBin::num(), BaseElement::new(REGISTERS_INDICES[7] as u128)], // tmp_h[7]
    ]
}

// Set s1 to 80 register
fn calc_s1() -> Vec<[BaseElement; 2]> {
    vec![
        [ToBin::num(), BaseElement::new(REGISTERS_INDICES[4] as u128)],
        [ROR::num(), BaseElement::new(0)],
        [ROR::num(), BaseElement::new(0)],
        [ROR::num(), BaseElement::new(0)],
        [ROR::num(), BaseElement::new(0)],
        [ROR::num(), BaseElement::new(0)],
        [ROR::num(), BaseElement::new(0)], // in B1 tmp_h[4].rotate_right(6)
        [FromBin::num(), BaseElement::new(REGISTERS_INDICES[8] as u128)],
        [ROR::num(), BaseElement::new(0)],
        [ROR::num(), BaseElement::new(0)],
        [ROR::num(), BaseElement::new(0)],
        [ROR::num(), BaseElement::new(0)],
        [ROR::num(), BaseElement::new(0)], // in B1 tmp_h[4].rotate_right(11)
        [FromBin::num(), BaseElement::new(REGISTERS_INDICES[9] as u128)], 
        [ROR::num(), BaseElement::new(0)],
        [ROR::num(), BaseElement::new(0)],
        [ROR::num(), BaseElement::new(0)],
        [ROR::num(), BaseElement::new(0)],
        [ROR::num(), BaseElement::new(0)],
        [ROR::num(), BaseElement::new(0)],
        [ROR::num(), BaseElement::new(0)],
        [ROR::num(), BaseElement::new(0)],
        [ROR::num(), BaseElement::new(0)],
        [ROR::num(), BaseElement::new(0)],
        [ROR::num(), BaseElement::new(0)],
        [ROR::num(), BaseElement::new(0)],
        [ROR::num(), BaseElement::new(0)],
        [ROR::num(), BaseElement::new(0)], // in B1 tmp_h[4].rotate_right(25)
        [ToBin2::num(), BaseElement::new(REGISTERS_INDICES[8] as u128)],
        [XOR::num(), BaseElement::new(0)],
        [ToBin2::num(), BaseElement::new(REGISTERS_INDICES[9] as u128)],
        [XOR::num(), BaseElement::new(0)],
        [FromBin::num(), BaseElement::new(REGISTERS_INDICES[8] as u128)],
    ]
}

// Set ch to 81 register
fn calc_ch() -> Vec<[BaseElement; 2]> {
    vec![
        [ToBin::num(), BaseElement::new(REGISTERS_INDICES[4] as u128)],
        [ToBin2::num(), BaseElement::new(REGISTERS_INDICES[5] as u128)],
        [AND::num(), BaseElement::new(0)],
        [FromBin::num(), BaseElement::new(REGISTERS_INDICES[9] as u128)],
        [ToBin::num(), BaseElement::new(REGISTERS_INDICES[4] as u128)],
        [ToBin2::num(), BaseElement::new(REGISTERS_INDICES[6] as u128)],
        [NOT::num(), BaseElement::new(0)],
        [AND::num(), BaseElement::new(0)],
        [ToBin2::num(), BaseElement::new(REGISTERS_INDICES[9] as u128)],
        [XOR::num(), BaseElement::new(0)],
        [FromBin::num(), BaseElement::new(REGISTERS_INDICES[9] as u128)],
    ]
}

// Set temp1 to 80 register
fn calc_temp1(i: usize) -> Vec<[BaseElement; 2]> {
    vec![
        [ToBin::num(), BaseElement::new(REGISTERS_INDICES[7] as u128)],
        [ToBin2::num(), BaseElement::new(REGISTERS_INDICES[8] as u128)],
        [ADD::num(), BaseElement::new(0)],
        [ToBin2::num(), BaseElement::new(REGISTERS_INDICES[9] as u128)],
        [ADD::num(), BaseElement::new(0)],
        [SetB2::num(), BaseElement::new(K[i] as u128)],
        [ADD::num(), BaseElement::new(0)],
        [ToBin2::num(), BaseElement::new(HARD_MEMORY_INDICES[i % 16] as u128)],
        [ADD::num(), BaseElement::new(0)],
        [FromBin::num(), BaseElement::new(REGISTERS_INDICES[8] as u128)],
    ]
}

// Set s0 to 81 register
fn calc_s0() -> Vec<[BaseElement; 2]> {
    vec![
        [ToBin::num(), BaseElement::new(REGISTERS_INDICES[0] as u128)],
        [ROR::num(), BaseElement::new(0)],
        [ROR::num(), BaseElement::new(0)], // in B1 tmp_h[0].rotate_right(2)
        [FromBin::num(), BaseElement::new(REGISTERS_INDICES[9] as u128)],
        [ROR::num(), BaseElement::new(0)],
        [ROR::num(), BaseElement::new(0)],
        [ROR::num(), BaseElement::new(0)],
        [ROR::num(), BaseElement::new(0)],
        [ROR::num(), BaseElement::new(0)],
        [ROR::num(), BaseElement::new(0)],
        [ROR::num(), BaseElement::new(0)],
        [ROR::num(), BaseElement::new(0)],
        [ROR::num(), BaseElement::new(0)],
        [ROR::num(), BaseElement::new(0)],
        [ROR::num(), BaseElement::new(0)], // in B1 tmp_h[0].rotate_right(13)
        [FromBin::num(), BaseElement::new(REGISTERS_INDICES[10] as u128)], 
        [ROR::num(), BaseElement::new(0)],
        [ROR::num(), BaseElement::new(0)],
        [ROR::num(), BaseElement::new(0)],
        [ROR::num(), BaseElement::new(0)],
        [ROR::num(), BaseElement::new(0)],
        [ROR::num(), BaseElement::new(0)],
        [ROR::num(), BaseElement::new(0)],
        [ROR::num(), BaseElement::new(0)],
        [ROR::num(), BaseElement::new(0)], // in B1 tmp_h[0].rotate_right(22)
        [ToBin2::num(), BaseElement::new(REGISTERS_INDICES[10] as u128)],
        [XOR::num(), BaseElement::new(0)],
        [ToBin2::num(), BaseElement::new(REGISTERS_INDICES[9] as u128)],
        [XOR::num(), BaseElement::new(0)],
        [FromBin::num(), BaseElement::new(REGISTERS_INDICES[9] as u128)],
    ]
}

// Set maj to 82 register
fn calc_maj() -> Vec<[BaseElement; 2]> {
    vec![
        [ToBin::num(), BaseElement::new(REGISTERS_INDICES[0] as u128)],
        [ToBin2::num(), BaseElement::new(REGISTERS_INDICES[1] as u128)],
        [AND::num(), BaseElement::new(0)],
        [FromBin::num(), BaseElement::new(REGISTERS_INDICES[10] as u128)],
        [ToBin::num(), BaseElement::new(REGISTERS_INDICES[0] as u128)],
        [ToBin2::num(), BaseElement::new(REGISTERS_INDICES[2] as u128)],
        [AND::num(), BaseElement::new(0)],
        [FromBin::num(), BaseElement::new(REGISTERS_INDICES[11] as u128)],
        [ToBin::num(), BaseElement::new(REGISTERS_INDICES[1] as u128)],
        [ToBin2::num(), BaseElement::new(REGISTERS_INDICES[2] as u128)],
        [AND::num(), BaseElement::new(0)],
        [ToBin2::num(), BaseElement::new(REGISTERS_INDICES[11] as u128)],
        [XOR::num(), BaseElement::new(0)],
        [ToBin2::num(), BaseElement::new(REGISTERS_INDICES[10] as u128)],
        [XOR::num(), BaseElement::new(0)],
        [FromBin::num(), BaseElement::new(REGISTERS_INDICES[10] as u128)],
    ]
}

// Set temp2 to 81 register
fn calc_temp2() -> Vec<[BaseElement; 2]> {
    vec![
        [ToBin::num(), BaseElement::new(REGISTERS_INDICES[9] as u128)],
        [ToBin2::num(), BaseElement::new(REGISTERS_INDICES[10] as u128)],
        [ADD::num(), BaseElement::new(0)],
        [FromBin::num(), BaseElement::new(REGISTERS_INDICES[9] as u128)],
    ]
}

fn update_w_i(i: usize) -> Vec<[BaseElement; 2]> {
    /*
        let s0 = (w[i - 15].rotate_right(7)) ^ (w[i - 15].rotate_right(18)) ^ (w[i - 15] >> 3);
        let s1 = (w[i - 2].rotate_right(17)) ^ (w[i - 2].rotate_right(19)) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
    */
    vec![
        [ToBin::num(), BaseElement::new(HARD_MEMORY_INDICES[(i - 15) % 16] as u128)],
        [ROR::num(), BaseElement::new(0)],
        [ROR::num(), BaseElement::new(0)],
        [ROR::num(), BaseElement::new(0)],
        [ROR::num(), BaseElement::new(0)],
        [ROR::num(), BaseElement::new(0)],
        [ROR::num(), BaseElement::new(0)],
        [ROR::num(), BaseElement::new(0)],
        [FromBin::num(), BaseElement::new(REGISTERS_INDICES[8] as u128)],
        [ROR::num(), BaseElement::new(0)],
        [ROR::num(), BaseElement::new(0)],
        [ROR::num(), BaseElement::new(0)],
        [ROR::num(), BaseElement::new(0)],
        [ROR::num(), BaseElement::new(0)],
        [ROR::num(), BaseElement::new(0)],
        [ROR::num(), BaseElement::new(0)],
        [ROR::num(), BaseElement::new(0)],
        [ROR::num(), BaseElement::new(0)],
        [ROR::num(), BaseElement::new(0)],
        [ROR::num(), BaseElement::new(0)],
        [FromBin::num(), BaseElement::new(REGISTERS_INDICES[9] as u128)],
        [ToBin::num(), BaseElement::new(HARD_MEMORY_INDICES[(i - 15) % 16] as u128)],
        [SHR::num(), BaseElement::new(0)],
        [SHR::num(), BaseElement::new(0)],
        [SHR::num(), BaseElement::new(0)],
        [ToBin2::num(), BaseElement::new(REGISTERS_INDICES[8] as u128)],
        [XOR::num(), BaseElement::new(0)],
        [ToBin2::num(), BaseElement::new(REGISTERS_INDICES[9] as u128)],
        [XOR::num(), BaseElement::new(0)],
        [FromBin::num(), BaseElement::new(REGISTERS_INDICES[8] as u128)], // save s0 to r0

        [ToBin::num(), BaseElement::new(HARD_MEMORY_INDICES[(i - 2) % 16] as u128)],
        [ROR::num(), BaseElement::new(0)],
        [ROR::num(), BaseElement::new(0)],
        [ROR::num(), BaseElement::new(0)],
        [ROR::num(), BaseElement::new(0)],
        [ROR::num(), BaseElement::new(0)],
        [ROR::num(), BaseElement::new(0)],
        [ROR::num(), BaseElement::new(0)],
        [ROR::num(), BaseElement::new(0)],
        [ROR::num(), BaseElement::new(0)],
        [ROR::num(), BaseElement::new(0)],
        [ROR::num(), BaseElement::new(0)],
        [ROR::num(), BaseElement::new(0)],
        [ROR::num(), BaseElement::new(0)],
        [ROR::num(), BaseElement::new(0)],
        [ROR::num(), BaseElement::new(0)],
        [ROR::num(), BaseElement::new(0)],
        [ROR::num(), BaseElement::new(0)],
        [FromBin::num(), BaseElement::new(REGISTERS_INDICES[9] as u128)],
        [ROR::num(), BaseElement::new(0)],
        [ROR::num(), BaseElement::new(0)],
        [FromBin::num(), BaseElement::new(REGISTERS_INDICES[10] as u128)],
        [ToBin::num(), BaseElement::new(HARD_MEMORY_INDICES[(i - 2) % 16] as u128)],
        [SHR::num(), BaseElement::new(0)],
        [SHR::num(), BaseElement::new(0)],
        [SHR::num(), BaseElement::new(0)],
        [SHR::num(), BaseElement::new(0)],
        [SHR::num(), BaseElement::new(0)],
        [SHR::num(), BaseElement::new(0)],
        [SHR::num(), BaseElement::new(0)],
        [SHR::num(), BaseElement::new(0)],
        [SHR::num(), BaseElement::new(0)],
        [SHR::num(), BaseElement::new(0)],
        [ToBin2::num(), BaseElement::new(REGISTERS_INDICES[9] as u128)],
        [XOR::num(), BaseElement::new(0)],
        [ToBin2::num(), BaseElement::new(REGISTERS_INDICES[10] as u128)],
        [XOR::num(), BaseElement::new(0)],
        [FromBin::num(), BaseElement::new(REGISTERS_INDICES[9] as u128)], // save s1 to r1

        [ToBin::num(), BaseElement::new(HARD_MEMORY_INDICES[i] as u128)],
        [ToBin2::num(), BaseElement::new(REGISTERS_INDICES[8] as u128)],
        [ADD::num(), BaseElement::new(0)],
        [ToBin2::num(), BaseElement::new(HARD_MEMORY_INDICES[(i - 7) % 16] as u128)],
        [ADD::num(), BaseElement::new(0)],
        [ToBin2::num(), BaseElement::new(REGISTERS_INDICES[9] as u128)],
        [ADD::num(), BaseElement::new(0)],
        [FromBin::num(), BaseElement::new(HARD_MEMORY_INDICES[i] as u128)],
    ]
}

fn update_tmp_h() -> Vec<[BaseElement; 2]> {
    vec![
        [ToBin::num(), BaseElement::new(REGISTERS_INDICES[6] as u128)],
        [FromBin::num(), BaseElement::new(REGISTERS_INDICES[7] as u128)],
        [ToBin::num(), BaseElement::new(REGISTERS_INDICES[5] as u128)],
        [FromBin::num(), BaseElement::new(REGISTERS_INDICES[6] as u128)],
        [ToBin::num(), BaseElement::new(REGISTERS_INDICES[4] as u128)],
        [FromBin::num(), BaseElement::new(REGISTERS_INDICES[5] as u128)],
        [ToBin::num(), BaseElement::new(REGISTERS_INDICES[3] as u128)],
        [ToBin2::num(), BaseElement::new(REGISTERS_INDICES[8] as u128)],
        [ADD::num(), BaseElement::new(0)],
        [FromBin::num(), BaseElement::new(REGISTERS_INDICES[4] as u128)],
        [ToBin::num(), BaseElement::new(REGISTERS_INDICES[2] as u128)],
        [FromBin::num(), BaseElement::new(REGISTERS_INDICES[3] as u128)],
        [ToBin::num(), BaseElement::new(REGISTERS_INDICES[1] as u128)],
        [FromBin::num(), BaseElement::new(REGISTERS_INDICES[2] as u128)],
        [ToBin::num(), BaseElement::new(REGISTERS_INDICES[0] as u128)],
        [FromBin::num(), BaseElement::new(REGISTERS_INDICES[1] as u128)],
        [ToBin::num(), BaseElement::new(REGISTERS_INDICES[8] as u128)],
        [ToBin2::num(), BaseElement::new(REGISTERS_INDICES[9] as u128)],
        [ADD::num(), BaseElement::new(0)],
        [FromBin::num(), BaseElement::new(REGISTERS_INDICES[0] as u128)],
    ]
}

fn update_h() -> Vec<[BaseElement; 2]> {
    vec![
        [ToBin::num(), BaseElement::new(IV_INDICES[0] as u128)],
        [ToBin2::num(), BaseElement::new(REGISTERS_INDICES[0] as u128)],
        [ADD::num(), BaseElement::new(0)],
        [FromBin::num(), BaseElement::new(IV_INDICES[0] as u128)],
        [ToBin::num(), BaseElement::new(IV_INDICES[1] as u128)],
        [ToBin2::num(), BaseElement::new(REGISTERS_INDICES[1] as u128)],
        [ADD::num(), BaseElement::new(0)],
        [FromBin::num(), BaseElement::new(IV_INDICES[1] as u128)],
        [ToBin::num(), BaseElement::new(IV_INDICES[2] as u128)],
        [ToBin2::num(), BaseElement::new(REGISTERS_INDICES[2] as u128)],
        [ADD::num(), BaseElement::new(0)],
        [FromBin::num(), BaseElement::new(IV_INDICES[2] as u128)],
        [ToBin::num(), BaseElement::new(IV_INDICES[3] as u128)],
        [ToBin2::num(), BaseElement::new(REGISTERS_INDICES[3] as u128)],
        [ADD::num(), BaseElement::new(0)],
        [FromBin::num(), BaseElement::new(IV_INDICES[3] as u128)],
        [ToBin::num(), BaseElement::new(IV_INDICES[4] as u128)],
        [ToBin2::num(), BaseElement::new(REGISTERS_INDICES[4] as u128)],
        [ADD::num(), BaseElement::new(0)],
        [FromBin::num(), BaseElement::new(IV_INDICES[4] as u128)],
        [ToBin::num(), BaseElement::new(IV_INDICES[5] as u128)],
        [ToBin2::num(), BaseElement::new(REGISTERS_INDICES[5] as u128)],
        [ADD::num(), BaseElement::new(0)],
        [FromBin::num(), BaseElement::new(IV_INDICES[5] as u128)],
        [ToBin::num(), BaseElement::new(IV_INDICES[6] as u128)],
        [ToBin2::num(), BaseElement::new(REGISTERS_INDICES[6] as u128)],
        [ADD::num(), BaseElement::new(0)],
        [FromBin::num(), BaseElement::new(IV_INDICES[6] as u128)],
        [ToBin::num(), BaseElement::new(IV_INDICES[7] as u128)],
        [ToBin2::num(), BaseElement::new(REGISTERS_INDICES[7] as u128)],
        [ADD::num(), BaseElement::new(0)],
        [FromBin::num(), BaseElement::new(IV_INDICES[7] as u128)],
    ]
}

fn hash_one_round(i: usize) -> Vec<[BaseElement; 2]> {
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

pub fn get_program() -> Vec<[BaseElement; 2]> {
    let mut program = Vec::new();
    program.extend(vec![[NOP::num(), BaseElement::new(0)]; 1]);
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
    program.extend(vec![[ResetHardMemory::num(), BaseElement::new(0)]; program.len().next_power_of_two() - program.len()]);
    program
}
