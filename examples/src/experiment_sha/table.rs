use std::iter::zip;

use crate::experiment_sha::utis::element_to_u32;

use super::BaseElement;

/* 
Table structure

00..63  columns - array of w    // hard memory
64..71  columns - iv            // ram
72..87  columns - tmp variables // registers
88..151 columns - bitregistres  // bit registers

*/

pub const HARD_MEMORY_LEN: usize = 64;
pub const HARD_MEMORY_START: usize = 0;

pub const HARD_MEMORY_INDICES: [usize; HARD_MEMORY_LEN] = {
    let mut indices = [0; HARD_MEMORY_LEN];
    let mut i = 0;
    while i < HARD_MEMORY_LEN {
        indices[i] = i;
        i += 1;
    }
    indices
};

pub const IV_LEN: usize = 8;
pub const IV_START: usize = HARD_MEMORY_START + HARD_MEMORY_LEN;

pub const IV_INDICES: [usize; IV_LEN] = {
    let mut indices = [0; IV_LEN];
    let mut i = 0;
    while i < IV_LEN {
        indices[i] = IV_START + i;
        i += 1;
    }
    indices
};

pub const REGISTERS_COUNT: usize = 16;
pub const REGISTERS_SIZE: usize = 1;
pub const REGISTERS_LEN: usize = REGISTERS_COUNT * REGISTERS_SIZE;
pub const REGISTERS_START: usize = IV_START + IV_LEN;

pub const REGISTERS_INDICES: [usize; REGISTERS_LEN] = {
    let mut indices = [0; REGISTERS_LEN];
    let mut i = 0;
    while i < REGISTERS_LEN {
        indices[i] = REGISTERS_START + i;
        i += 1;
    }
    indices
};

pub const VARIABLES_COUNT: usize = REGISTERS_START + REGISTERS_LEN;

pub const BIT_REGISTERS_COUNT: usize = 2;
pub const BIT_REGISTERS_SIZE: usize = 32;
pub const BIT_REGISTERS_LEN: usize = BIT_REGISTERS_COUNT * BIT_REGISTERS_SIZE;
pub const BIT_REGISTERS_START: usize = REGISTERS_START + REGISTERS_LEN;

pub const B1: [usize; BIT_REGISTERS_SIZE] = {
    let mut indices = [0; BIT_REGISTERS_SIZE];
    let mut i = 0;
    while i < BIT_REGISTERS_SIZE {
        indices[i] = BIT_REGISTERS_START + BIT_REGISTERS_SIZE * 0 + i;
        i += 1;
    }
    indices
};

pub const B2: [usize; BIT_REGISTERS_SIZE] = {
    let mut indices = [0; BIT_REGISTERS_SIZE];
    let mut i = 0;
    while i < BIT_REGISTERS_SIZE {
        indices[i] = BIT_REGISTERS_START + BIT_REGISTERS_SIZE * 1 + i;
        i += 1;
    }
    indices
};

pub const VM_COLUMNS: usize = BIT_REGISTERS_START + BIT_REGISTERS_LEN;

pub const TABLE_WIDTH: usize = VM_COLUMNS;

pub const INPUT_STRING_LENGTH: usize = 64;
pub const INPUT_BASE_ELEMENTS: usize = INPUT_STRING_LENGTH / 4;

pub fn set_to_bit_register(state: &mut [BaseElement], u: BaseElement, b: [usize; BIT_REGISTERS_SIZE]) {
    let mut a = element_to_u32(u);
    for i in b {
        state[i] = BaseElement::new((a & 1) as u128);
        a /= 2;
    }
}

pub fn set_to_bit_register_b2(state: &mut [BaseElement], u: BaseElement) {
    set_to_bit_register(state, u, B2);
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

pub fn xor_bit_registers(state: &mut [BaseElement]) {
    for i in zip(B1, B2) {
        state[i.0] = BaseElement::new((element_to_u32(state[i.0]) ^ element_to_u32(state[i.1])) as u128);
    }
}

pub fn and_bit_registers(state: &mut [BaseElement]) {
    for i in zip(B1, B2) {
        state[i.0] = BaseElement::new((element_to_u32(state[i.0]) & element_to_u32(state[i.1])) as u128);
    }
}

pub fn or_bit_registers(state: &mut [BaseElement]) {
    for i in zip(B1, B2) {
        state[i.0] = BaseElement::new((element_to_u32(state[i.0]) | element_to_u32(state[i.1])) as u128);
    }
}

pub fn not_bit_registers(state: &mut [BaseElement]) {
    for i in B1 {
        state[i] = BaseElement::new((1 - element_to_u32(state[i])) as u128);
    }
}

pub fn ror_bit_registers(state: &mut [BaseElement]) {
    // Циклический сдвиг вправо: младший бит становится старшим
    let mut bits = [0u32; BIT_REGISTERS_SIZE];
    
    // Читаем все биты из B1
    for (i, &idx) in B1.iter().enumerate() {
        bits[i] = element_to_u32(state[idx]);
    }
    
    // Выполняем циклический сдвиг вправо
    let lsb = bits[0]; // Сохраняем младший бит
    for i in 0..BIT_REGISTERS_SIZE - 1 {
        bits[i] = bits[i + 1]; // Сдвигаем все биты вправо
    }
    bits[BIT_REGISTERS_SIZE - 1] = lsb; // Младший бит становится старшим
    
    // Записываем результат обратно в B1
    for (i, &idx) in B1.iter().enumerate() {
        state[idx] = BaseElement::new(bits[i] as u128);
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
        state[idx] = BaseElement::new(bits[i] as u128);
    }
}

pub fn add_bit_registers(state: &mut [BaseElement]) {
    // Сложение B1 + B2 по модулю 2^32, результат в B1
    let mut b1_bits = [0u32; BIT_REGISTERS_SIZE];
    let mut b2_bits = [0u32; BIT_REGISTERS_SIZE];
    
    // Читаем все биты из B1 и B2
    for (i, &idx) in B1.iter().enumerate() {
        b1_bits[i] = element_to_u32(state[idx]);
    }
    for (i, &idx) in B2.iter().enumerate() {
        b2_bits[i] = element_to_u32(state[idx]);
    }
    
    // Преобразуем биты в u32 числа
    let mut b1_value = 0u32;
    let mut b2_value = 0u32;
    
    for i in 0..BIT_REGISTERS_SIZE {
        b1_value |= b1_bits[i] << i;
        b2_value |= b2_bits[i] << i;
    }
    
    // Выполняем сложение по модулю 2^32
    let result = b1_value.wrapping_add(b2_value);
    
    // Разбиваем результат обратно на биты и записываем в B1
    for (i, &idx) in B1.iter().enumerate() {
        let bit = (result >> i) & 1;
        state[idx] = BaseElement::new(bit as u128);
    }
}

pub fn set_iv(state: &mut [BaseElement], iv: [BaseElement; IV_LEN]) {
    for i in 0..iv.len() {
        state[IV_INDICES[i]] = iv[i];
    }
}
