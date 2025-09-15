use winterfell::Assertion;

use crate::experiment_sha::{table::IV_INDICES, utis::{extend_sha256_block, get_iv}, vm_program::PROGRAM_LEN};

use super::BaseElement;

pub const INPUT_ASSERTIONS_LEN: usize = 64;
pub const RESULT_ASSERTIONS_LEN: usize = 8;
pub const IV_ASSERTIONS_LEN: usize = 8;

pub const ASSERTIONS_LEN: usize = INPUT_ASSERTIONS_LEN + RESULT_ASSERTIONS_LEN + IV_ASSERTIONS_LEN;

pub fn push_static_assertions(assertions: &mut Vec<Assertion<BaseElement>>) {
    let iv = get_iv();
    for i in 0..iv.len() {
        assertions.push(Assertion::single(IV_INDICES[i], 0, iv[i]));
    }
}

pub fn push_input_assertions(input: Vec<[BaseElement; 16]>, assertions: &mut Vec<Assertion<BaseElement>>) {
    let mut input_assertions: Vec<Vec<BaseElement>> = vec![vec![]; INPUT_ASSERTIONS_LEN];
    for i in input {
        let d = extend_sha256_block(i.to_vec());    
        for j in 0..d.len() {
            input_assertions[j].push(d[j]);
        }
    }
    for i in 0..INPUT_ASSERTIONS_LEN {
        // println!("input_assertions[{}] = {:?}", i, input_assertions[i]);
        assertions.push(Assertion::sequence(i, 0, PROGRAM_LEN, input_assertions[i].clone()));
    }
}

pub fn push_result_assertions(result: Vec<BaseElement>, assertions: &mut Vec<Assertion<BaseElement>>, last_step: usize) {
    for i in 0..RESULT_ASSERTIONS_LEN {
        assertions.push(Assertion::single(IV_INDICES[i], last_step, result[i]));
    }
}
