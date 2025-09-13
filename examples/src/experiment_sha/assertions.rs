use winterfell::Assertion;

use crate::experiment_sha::{table::{IV_INDICES}, utis::get_iv};

use super::BaseElement;

pub const INPUT_ASSERTIONS_LEN: usize = 64;
pub const RESULT_ASSERTIONS_LEN: usize = 8;
pub const IV_ASSERTIONS_LEN: usize = 8;
// pub const PROGRAM_ASSERTIONS_LEN: usize = PROGRAM_LEN * PROGRAM_COLUMNS_LEN;

pub const ASSERTIONS_LEN: usize = INPUT_ASSERTIONS_LEN + RESULT_ASSERTIONS_LEN + IV_ASSERTIONS_LEN /* + PROGRAM_ASSERTIONS_LEN */;

pub fn push_program_assertions(assertions: &mut Vec<Assertion<BaseElement>>) {
    let iv = get_iv();
    for i in 0..iv.len() {
        assertions.push(Assertion::single(IV_INDICES[i], 0, iv[i]));
    }
    /*
    for (i, row) in get_program().iter().enumerate() {
        for j in 0..PROGRAM_COLUMNS_LEN {
            assertions.push(Assertion::periodic(PROGRAM_INDICES[j], i, PROGRAM_LEN, row[j]));
        }
    }
    */
}