use crate::experiment_sha::table_constants::*;


// TRANSITIONS

pub const SET_B2_VALUES: usize = 1;
pub const PERIODIC_VALUES_START: usize = SET_B2_VALUES;

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
pub const PERIODIC_MEMORY_COLUMNS_START: usize = PERIODIC_VALUES_START;
pub const PERIODIC_MEMORY_COLUMNS_LEN: usize = MEMORY_TRANSITIONS_LEN;
pub const PERIODIC_MEMORY_COLUMNS_INDICES: [usize; PERIODIC_MEMORY_COLUMNS_LEN] = {
    let mut indices = [0; PERIODIC_MEMORY_COLUMNS_LEN];
    let mut i = 0;
    while i < PERIODIC_MEMORY_COLUMNS_LEN {
        indices[i] = PERIODIC_MEMORY_COLUMNS_START + i;
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

pub const PERIODIC_BIT_MEMORY_COLUMNS_START: usize = PERIODIC_MEMORY_COLUMNS_START + PERIODIC_MEMORY_COLUMNS_LEN;
pub const PERIODIC_BIT_MEMORY_COLUMNS_LEN: usize = BIT_MEMORY_TRANSITIONS_LEN;
pub const PERIODIC_BIT_MEMORY_COLUMNS_INDICES: [usize; PERIODIC_BIT_MEMORY_COLUMNS_LEN] = {
    let mut indices = [0; PERIODIC_BIT_MEMORY_COLUMNS_LEN];
    let mut i = 0;
    while i < PERIODIC_BIT_MEMORY_COLUMNS_LEN {
        indices[i] = PERIODIC_BIT_MEMORY_COLUMNS_START + i;
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

pub const PERIODIC_CHECK_BIT_COLUMNS_START: usize = PERIODIC_BIT_MEMORY_COLUMNS_START + PERIODIC_BIT_MEMORY_COLUMNS_LEN;
pub const PERIODIC_CHECK_BIT_COLUMNS_LEN: usize = 0;
pub const PERIODIC_CHECK_BIT_COLUMNS_INDICES: [usize; PERIODIC_CHECK_BIT_COLUMNS_LEN] = {
    let mut indices = [0; PERIODIC_CHECK_BIT_COLUMNS_LEN];
    let mut i = 0;
    while i < PERIODIC_CHECK_BIT_COLUMNS_LEN {
        indices[i] = PERIODIC_CHECK_BIT_COLUMNS_START + i;
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

pub const PERIODIC_TO_B1_COLUMNS_START: usize = PERIODIC_CHECK_BIT_COLUMNS_START + PERIODIC_CHECK_BIT_COLUMNS_LEN;
pub const PERIODIC_TO_B1_COLUMNS_LEN: usize = TO_B1_TRANSITIONS_LEN;
pub const PERIODIC_TO_B1_COLUMNS_INDICES: [usize; PERIODIC_TO_B1_COLUMNS_LEN] = {
    let mut indices = [0; PERIODIC_TO_B1_COLUMNS_LEN];
    let mut i = 0;
    while i < PERIODIC_TO_B1_COLUMNS_LEN {
        indices[i] = PERIODIC_TO_B1_COLUMNS_START + i;
        i += 1;
    }
    indices
};

// Битовая информация для переменных
pub const FROM_BIN_TRANSITIONS_LEN: usize = VARIABLES_COUNT;
pub const FROM_BIN_TRANSITIONS_START: usize = TO_B1_TRANSITIONS_START + TO_B1_TRANSITIONS_LEN;
pub const FROM_BIN_TRANSITIONS_INDICES: [usize; FROM_BIN_TRANSITIONS_LEN] = {
    let mut indices = [0; FROM_BIN_TRANSITIONS_LEN];
    let mut i = 0;
    while i < FROM_BIN_TRANSITIONS_LEN {
        indices[i] = FROM_BIN_TRANSITIONS_START + i;
        i += 1;
    }
    indices
};

pub const PERIODIC_FROM_BIN_COLUMNS_START: usize = PERIODIC_TO_B1_COLUMNS_START + PERIODIC_TO_B1_COLUMNS_LEN;
pub const PERIODIC_FROM_BIN_COLUMNS_LEN: usize = FROM_BIN_TRANSITIONS_LEN;
pub const PERIODIC_FROM_BIN_COLUMNS_INDICES: [usize; PERIODIC_FROM_BIN_COLUMNS_LEN] = {
    let mut indices = [0; PERIODIC_FROM_BIN_COLUMNS_LEN];
    let mut i = 0;
    while i < PERIODIC_FROM_BIN_COLUMNS_LEN {
        indices[i] = PERIODIC_FROM_BIN_COLUMNS_START + i;
        i += 1;
    }
    indices
};

pub const XOR_TRANSITIONS_LEN: usize = REGISTERS_COUNT;
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

pub const PERIODIC_XOR_COLUMNS_START: usize = PERIODIC_FROM_BIN_COLUMNS_START + PERIODIC_FROM_BIN_COLUMNS_LEN;
pub const PERIODIC_XOR_COLUMNS_LEN: usize = XOR_TRANSITIONS_LEN;
pub const PERIODIC_XOR_COLUMNS_INDICES: [usize; PERIODIC_XOR_COLUMNS_LEN] = {
    let mut indices = [0; PERIODIC_XOR_COLUMNS_LEN];
    let mut i = 0;
    while i < PERIODIC_XOR_COLUMNS_LEN {
        indices[i] = PERIODIC_XOR_COLUMNS_START + i;
        i += 1;
    }
    indices
};


pub const AND_TRANSITIONS_LEN: usize = REGISTERS_COUNT;
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

pub const PERIODIC_AND_COLUMNS_START: usize = PERIODIC_XOR_COLUMNS_START + PERIODIC_XOR_COLUMNS_LEN;
pub const PERIODIC_AND_COLUMNS_LEN: usize = AND_TRANSITIONS_LEN;
pub const PERIODIC_AND_COLUMNS_INDICES: [usize; PERIODIC_AND_COLUMNS_LEN] = {
    let mut indices = [0; PERIODIC_AND_COLUMNS_LEN];
    let mut i = 0;
    while i < PERIODIC_AND_COLUMNS_LEN {
        indices[i] = PERIODIC_AND_COLUMNS_START + i;
        i += 1;
    }
    indices
};

pub const NOT_TRANSITIONS_LEN: usize = BIT_REGISTERS_SIZE;
pub const NOT_TRANSITIONS_START: usize = AND_TRANSITIONS_START + AND_TRANSITIONS_LEN;
pub const NOT_TRANSITIONS_INDICES: [usize; NOT_TRANSITIONS_LEN] = {
    let mut indices = [0; NOT_TRANSITIONS_LEN];
    let mut i = 0;
    while i < NOT_TRANSITIONS_LEN {
        indices[i] = NOT_TRANSITIONS_START + i;
        i += 1;
    }
    indices
};

pub const PERIODIC_NOT_COLUMNS_START: usize = PERIODIC_AND_COLUMNS_START + PERIODIC_AND_COLUMNS_LEN;
pub const PERIODIC_NOT_COLUMNS_LEN: usize = 1;
pub const PERIODIC_NOT_COLUMNS_INDICES: [usize; PERIODIC_NOT_COLUMNS_LEN] = {
    let mut indices = [0; PERIODIC_NOT_COLUMNS_LEN];
    let mut i = 0;
    while i < PERIODIC_NOT_COLUMNS_LEN {
        indices[i] = PERIODIC_NOT_COLUMNS_START + i;
        i += 1;
    }
    indices
};


pub const ROR_TRANSITIONS_SHIFTS: [usize; 10] = [2, 6, 7, 11, 13, 17, 18, 19, 22, 25]; 
pub const ROR_TRANSITIONS_LEN: usize = ROR_TRANSITIONS_SHIFTS.len();
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

pub const PERIODIC_ROR_COLUMNS_START: usize = PERIODIC_NOT_COLUMNS_START + PERIODIC_NOT_COLUMNS_LEN;
pub const PERIODIC_ROR_COLUMNS_LEN: usize = ROR_TRANSITIONS_LEN;
pub const PERIODIC_ROR_COLUMNS_INDICES: [usize; PERIODIC_ROR_COLUMNS_LEN] = {
    let mut indices = [0; PERIODIC_ROR_COLUMNS_LEN];
    let mut i = 0;
    while i < PERIODIC_ROR_COLUMNS_LEN {
        indices[i] = PERIODIC_ROR_COLUMNS_START + i;
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

pub const PERIODIC_SHR_COLUMNS_START: usize = PERIODIC_ROR_COLUMNS_START + PERIODIC_ROR_COLUMNS_LEN;
pub const PERIODIC_SHR_COLUMNS_LEN: usize = 1;
pub const PERIODIC_SHR_COLUMNS_INDICES: [usize; PERIODIC_SHR_COLUMNS_LEN] = {
    let mut indices = [0; PERIODIC_SHR_COLUMNS_LEN];
    let mut i = 0;
    while i < PERIODIC_SHR_COLUMNS_LEN {
        indices[i] = PERIODIC_SHR_COLUMNS_START + i;
        i += 1;
    }
    indices
};

pub const ADD_1_TRANSITIONS_LEN: usize = 4;
pub const ADD_1_TRANSITIONS_START: usize = SHR_TRANSITIONS_START + SHR_TRANSITIONS_LEN;
pub const ADD_1_TRANSITIONS_INDICES: [usize; ADD_1_TRANSITIONS_LEN] = {
    let mut indices = [0; ADD_1_TRANSITIONS_LEN];
    let mut i = 0;
    while i < ADD_1_TRANSITIONS_LEN {
        indices[i] = ADD_1_TRANSITIONS_START + i;
        i += 1;
    }
    indices
};

pub const PERIODIC_ADD_1_COLUMNS_START: usize = PERIODIC_SHR_COLUMNS_START + PERIODIC_SHR_COLUMNS_LEN;
pub const PERIODIC_ADD_1_COLUMNS_LEN: usize = 1;
pub const PERIODIC_ADD_1_COLUMNS_INDICES: [usize; PERIODIC_ADD_1_COLUMNS_LEN] = {
    let mut indices = [0; PERIODIC_ADD_1_COLUMNS_LEN];
    let mut i = 0;
    while i < PERIODIC_ADD_1_COLUMNS_LEN {
        indices[i] = PERIODIC_ADD_1_COLUMNS_START + i;
        i += 1;
    }
    indices
};

pub const ADD_2_TRANSITIONS_LEN: usize = 2 + REGISTERS_COUNT;
pub const ADD_2_TRANSITIONS_START: usize = ADD_1_TRANSITIONS_START + ADD_1_TRANSITIONS_LEN;
pub const ADD_2_TRANSITIONS_INDICES: [usize; ADD_2_TRANSITIONS_LEN] = {
    let mut indices = [0; ADD_2_TRANSITIONS_LEN];
    let mut i = 0;
    while i < ADD_2_TRANSITIONS_LEN {
        indices[i] = ADD_2_TRANSITIONS_START + i;
        i += 1;
    }
    indices
};

pub const PERIODIC_ADD_2_COLUMNS_START: usize = PERIODIC_ADD_1_COLUMNS_START + PERIODIC_ADD_1_COLUMNS_LEN;
pub const PERIODIC_ADD_2_COLUMNS_LEN: usize = REGISTERS_COUNT;
pub const PERIODIC_ADD_2_COLUMNS_INDICES: [usize; PERIODIC_ADD_2_COLUMNS_LEN] = {
    let mut indices = [0; PERIODIC_ADD_2_COLUMNS_LEN];
    let mut i = 0;
    while i < PERIODIC_ADD_2_COLUMNS_LEN {
        indices[i] = PERIODIC_ADD_2_COLUMNS_START + i;
        i += 1;
    }
    indices
};

pub const SETB2_TRANSITIONS_LEN: usize = 1;
pub const SETB2_TRANSITIONS_START: usize = ADD_2_TRANSITIONS_START + ADD_2_TRANSITIONS_LEN;
pub const SETB2_TRANSITIONS_INDICES: [usize; SETB2_TRANSITIONS_LEN] = {
    let mut indices = [0; SETB2_TRANSITIONS_LEN];
    let mut i = 0;
    while i < SETB2_TRANSITIONS_LEN {
        indices[i] = SETB2_TRANSITIONS_START + i;
        i += 1;
    }
    indices
};


pub const PERIODIC_SETB2_COLUMNS_START: usize = PERIODIC_ADD_2_COLUMNS_START + PERIODIC_ADD_2_COLUMNS_LEN;
pub const PERIODIC_SETB2_COLUMNS_LEN: usize = 1;
pub const PERIODIC_SETB2_COLUMNS_INDICES: [usize; PERIODIC_SETB2_COLUMNS_LEN] = {
    let mut indices = [0; PERIODIC_SETB2_COLUMNS_LEN];
    let mut i = 0;
    while i < PERIODIC_SETB2_COLUMNS_LEN {
        indices[i] = PERIODIC_SETB2_COLUMNS_START + i;
        i += 1;
    }
    indices
};
