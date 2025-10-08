use crate::experiment_sha::utis::element_to_u32;
use crate::experiment_sha::table_constants::*;

use super::BaseElement;

pub fn set_to_bit_register(state: &mut [BaseElement], u: BaseElement, b: [usize; BIT_REGISTERS_SIZE]) {
    let mut a = element_to_u32(u);
    for i in b {
        state[i] = BaseElement::new((a & 1) as u64);
        a /= 2;
    }
}


pub fn set_from_bit_register(state: &mut [BaseElement], u: usize, b: [usize; BIT_REGISTERS_SIZE]) {
    let two = BaseElement::new(2);
    let mut p = BaseElement::new(1);
    let mut in_register = BaseElement::new(0);
    for i in b {
        in_register += state[i] * p;
        p = two * p;
    }
    state[u] = in_register;
}

pub fn xor_bit_registers(initial_state: &[BaseElement], final_state: &mut [BaseElement], idx: usize) {
    let two = BaseElement::new(2);
    let mut p = BaseElement::new(1);
    let mut in_register = BaseElement::new(0);
    for i in B1 {
        in_register += BaseElement::new((element_to_u32(initial_state[i]) ^ element_to_u32(final_state[i])) as u64) * p;
        p = two * p;
    }
    final_state[idx] = in_register;
}

pub fn and_bit_registers(initial_state: &[BaseElement], final_state: &mut [BaseElement], idx: usize) {
    let two = BaseElement::new(2);
    let mut p = BaseElement::new(1);
    let mut in_register = BaseElement::new(0);
    for i in B1 {
        in_register += BaseElement::new((element_to_u32(initial_state[i]) & element_to_u32(final_state[i])) as u64) * p;
        p = two * p;
    }
    final_state[idx] = in_register;
}

pub fn not_bit_registers(state: &mut [BaseElement]) {
    for i in B1 {
        state[i] = BaseElement::new((1 - element_to_u32(state[i])) as u64);
    }
}

pub fn ror_bit_registers(state: &mut [BaseElement], shift: usize) {
    // Циклический сдвиг вправо: младший бит становится старшим
    let mut bits = [0u32; BIT_REGISTERS_SIZE];
    
    // Читаем все биты из B1
    for (i, &idx) in B1.iter().enumerate() {
        bits[i] = element_to_u32(state[idx]);
    }

    let mut new_bits = [0u32; BIT_REGISTERS_SIZE];
    for i in 0..BIT_REGISTERS_SIZE {
        new_bits[i] = bits[(i + shift) % BIT_REGISTERS_SIZE];
    }
    
    // Записываем результат обратно в B1
    for (i, &idx) in B1.iter().enumerate() {
        state[idx] = BaseElement::new(new_bits[i] as u64);
    }
}

pub fn shr_bit_registers(state: &mut [BaseElement]) {
    // Сдвиг вправо (деление на 2): старший бит становится 0
    let mut bits = [0u32; BIT_REGISTERS_SIZE];
    
    // Читаем все биты из B1
    for (i, &idx) in B1.iter().enumerate() {
        bits[i] = element_to_u32(state[idx]);
    }
    
    // Выполняем сдвиг вправо
    for i in 0..BIT_REGISTERS_SIZE - 1 {
        bits[i] = bits[i + 1]; // Сдвигаем все биты вправо
    }
    bits[BIT_REGISTERS_SIZE - 1] = 0; // Старший бит становится 0
    
    // Записываем результат обратно в B1
    for (i, &idx) in B1.iter().enumerate() {
        state[idx] = BaseElement::new(bits[i] as u64);
    }
}

pub fn set_iv(state: &mut [BaseElement], iv: [BaseElement; IV_LEN]) {
    for i in 0..iv.len() {
        state[IV_INDICES[i]] = iv[i];
    }
}
