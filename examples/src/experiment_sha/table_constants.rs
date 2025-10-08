/* 
Table structure

00..15  columns - array of w    // hard memory
16..23  columns - iv            // ram
24..35  columns - tmp variables // registers
36..99 columns - bitregistres  // bit registers

*/

pub const HARD_MEMORY_LEN: usize = 16;
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

pub const REGISTERS_COUNT: usize = 12;
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

pub const BIT_REGISTERS_COUNT: usize = 1;
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

pub const VM_COLUMNS: usize = BIT_REGISTERS_START + BIT_REGISTERS_LEN;

pub const TABLE_WIDTH: usize = VM_COLUMNS;

pub const INPUT_STRING_LENGTH: usize = 64;
pub const INPUT_BASE_ELEMENTS: usize = INPUT_STRING_LENGTH / 4;
