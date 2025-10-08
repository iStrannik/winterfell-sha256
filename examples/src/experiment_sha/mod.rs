// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use core::marker::PhantomData;

use tracing::{field, info_span};
use winterfell::{
    crypto::{DefaultRandomCoin, ElementHasher, MerkleTree},
    math::{fields::f64::BaseElement, FieldElement},
    Proof, ProofOptions, Prover, Trace, VerifierError,
};

use crate::{experiment_sha::{air::PublicInputs, table_constants::TABLE_WIDTH, utis::{bytes_to_elements, prepare_sha_256_block}}, Blake3_192F64, Blake3_256F64, Example, ExampleOptions, HashFunction, Sha3_256F64};

mod air;
mod assertions;
use air::ExperimentShaAir;
pub mod table_constants;
mod transitions_constants;
mod transitions;
mod utis;
mod table;
mod vm_program;
mod prover;
use prover::ExperimentShaProver;

pub fn custom_sha256(message: &[u8]) -> [u8; 32] {
    /* Предполагаемый вид таблицы:
    Первые колонки в строке - хешируемый блок данных(64 байта)
    За ним - хеш предыдущего шага хеширование (32 байта) Итого - 96 байт.
    Если использовать поле f128 - в элемент можно засунуть <= 15 байт без риска переполнения, 
    то есть в целом можно хранить по одному байту.
    - есть начальное значение iv
    - в блоке байты делятся на слова по 4(u32) - они формируют первые 16 слов в массиве w
    - остальные слова в w формируются на основе предыдущих вычислений w(нужно 4 значения - w[i - 15], w[i - 2], w[i - 16], w[i - 7])
    - всего происходит 64 итераций хеширования блока:
        - на каждой итерации преобразуется массив state из 8 u32 - суммарно 32 байта (256 бит) - на первой итерации это iv
        - для вычисления новых значений массива нужны только они и одно слово из w
    - после итераций к изначальному iv прибавляется state

    Таким образом для вычисления хеша необходимо протаскивать между строками хотя бы 32 байта(iv) + w(4 байта прикопать через assert либо полноценные 64 байта) + 32 байта(state)
    Итого: 128 байт * 8 = 1024 бита. Это 1024 колонок, если хранить по биту, либо 64 колонки, если хранить по 16 бит в одной колонке. 
    Два пути как с этим жить:
    - если использовать уже реализованные поля
        - по одному биту в элементе - это 65 * 8 = 520 столбцов - очень много и нерационально. Но все операции проводить очень легко
        - плотненько уложить по 15 байт в число, тогда понадобится всего 5 столбцов (или ещё проще просто по байту в столбец, тогда будет )


    Как можно упростить пруфинг:
    - на этапе преобразования строки сделать предподсчёт w и отправить их публичными данными(условнно добавить в колонку с инпутом, добавить на них assert).
    Как хешируется один блок:
    - 

    Функции, которые используются при хешировании:
    - &
    - сложение по модулю 2^32, 
    - циклический побитовый сдвиг вправо
    - побитовый сдвиг вправо
    - xor
    - ~
    -
    
     */

    // iv(начальное значение для блока) - 32 байта
    // размер хешируемого блока - 64 байта

    // окончательное формирование блоков - добавить байт 0x80, последние 8 байт заполнить длинной сообщение в битах
    let mut m = message.to_vec();
    m.push(0x80);
    if 64 - m.len() % 64 < 8 {
        m.append(&mut vec![0u8; 64 - m.len() % 64])
    }
    m.append(&mut vec![0u8; 64 - m.len() % 64 - 8]);
    m.append(&mut (message.len() as u64 * 8).to_be_bytes().to_vec());
    let blocks = m.chunks_exact(64);
    println!("blocks = {:?}", blocks.len());

    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ];

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

    // Итерация по блокам данных
    for block in blocks {
        // Объединение байтов u8 в набор u32
        let mut w: Vec<u32> = block.chunks_exact(4).map(|chunk| {
            u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]])
        }).collect();
        w.append(&mut vec![0u32; 48]);

        // Заполнение оставшихся 48 слов
        for i in 16..64 {
            let s0 = (w[i - 15].rotate_right(7)) ^ (w[i - 15].rotate_right(18)) ^ (w[i - 15] >> 3);
            let s1 = (w[i - 2].rotate_right(17)) ^ (w[i - 2].rotate_right(19)) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
        }

        // println!("initial w");
        // println!("{:?}", w.iter().map(|x| format!("{:x}", x)).collect::<Vec<String>>().join(" "));

        // println!("inishial h");
        // println!("{:?}", h.iter().map(|x| format!("{:x}", x)).collect::<Vec<String>>().join(" "));

        // a, b, c, d, e, f, g, h
        // 0, 1, 2, 3, 4, 5, 6, 7
        let mut tmp_h: [u32; 8] = h.clone();

        // 64 раунда хэширования
        for i in 0..64 {
            let s1 = (tmp_h[4].rotate_right(6)) ^ (tmp_h[4].rotate_right(11)) ^ (tmp_h[4].rotate_right(25));
            let ch = (tmp_h[4] & tmp_h[5]) ^ (!tmp_h[4] & tmp_h[6]);
            let temp1 = tmp_h[7].wrapping_add(s1).wrapping_add(ch).wrapping_add(K[i]).wrapping_add(w[i]);
            let s0 = (tmp_h[0].rotate_right(2)) ^ (tmp_h[0].rotate_right(13)) ^ (tmp_h[0].rotate_right(22));
            let maj = (tmp_h[0] & tmp_h[1]) ^ (tmp_h[0] & tmp_h[2]) ^ (tmp_h[1] & tmp_h[2]);
            let temp2 = s0.wrapping_add(maj);

            tmp_h[7] = tmp_h[6];
            tmp_h[6] = tmp_h[5];
            tmp_h[5] = tmp_h[4];
            tmp_h[4] = tmp_h[3].wrapping_add(temp1);
            tmp_h[3] = tmp_h[2];
            tmp_h[2] = tmp_h[1];
            tmp_h[1] = tmp_h[0];
            tmp_h[0] = temp1.wrapping_add(temp2);
        }

        for i in 0..8 {
            h[i] = h[i].wrapping_add(tmp_h[i]);
        }
    }

    h.map(|chunk| chunk.to_be_bytes()).concat().as_slice().try_into().unwrap()
}


// EXPERIMENT SHA EXAMPLE
// ================================================================================================

pub fn get_example(
    options: &ExampleOptions,
    string_length: usize,
) -> Result<Box<dyn Example>, String> {
    let (options, hash_fn) = options.to_proof_options(28, 8);

    match hash_fn {
        HashFunction::Blake3_192 => {
            Ok(Box::new(ExperimentShaExample::<Blake3_192F64>::new(string_length, options)))
        },
        HashFunction::Blake3_256 => {
            Ok(Box::new(ExperimentShaExample::<Blake3_256F64>::new(string_length, options)))
        },
        HashFunction::Sha3_256 => {
            Ok(Box::new(ExperimentShaExample::<Sha3_256F64>::new(string_length, options)))
        },
        _ => Err("The specified hash function cannot be used with this example.".to_string()),
    }
}

pub struct ExperimentShaExample<H: ElementHasher> {
    options: ProofOptions,
    input_data: Vec<[BaseElement; 16]>,
    result: Vec<BaseElement>,
    _hasher: PhantomData<H>,
}

impl<H: ElementHasher> ExperimentShaExample<H> {
    pub fn new(string_length: usize, options: ProofOptions) -> Self {
        let input_string = "a".repeat(string_length).to_string();
        let input_data = prepare_sha_256_block(&input_string)
            .chunks(16)
            .map(|chunk| {
                let arr: [BaseElement; 16] = chunk
                    .iter()
                    .cloned()
                    .collect::<Vec<BaseElement>>()
                    .try_into()
                    .expect("Chunk should have exactly 16 elements");
                arr
            })
            .collect::<Vec<[BaseElement; 16]>>();
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(input_string.as_bytes());
        let hash_result = hasher.finalize();
        println!("sha256(input_string) = {}", hex::encode(hash_result));
        // println!("custom_sha256(input_string) = {}", hex::encode(custom_sha256(input_string.as_bytes())));
        ExperimentShaExample {
            options,
            input_data,
            result: bytes_to_elements(hash_result.as_slice()),
            _hasher: PhantomData,
        }
    }
}

// EXAMPLE IMPLEMENTATION
// ================================================================================================

impl<H: ElementHasher> Example for ExperimentShaExample<H>
where
    H: ElementHasher<BaseField = BaseElement> + Sync,
{
    fn prove(&self) -> Proof {
        // create a prover
        let prover = ExperimentShaProver::<H>::new(self.options.clone());

        // generate execution trace
        let trace =
            info_span!("generate_execution_trace", num_cols = TABLE_WIDTH, steps = field::Empty)
                .in_scope(|| {
                    let trace = prover.build_trace( PublicInputs { data: self.input_data.clone(), result: self.result.clone() } );
                    tracing::Span::current().record("steps", trace.length());
                    trace
                });

        // generate the proof
        prover.prove(trace).unwrap()
    }

    fn verify(&self, proof: Proof) -> Result<(), VerifierError> {
        let acceptable_options =
            winterfell::AcceptableOptions::OptionSet(vec![proof.options().clone()]);

        winterfell::verify::<ExperimentShaAir, H, DefaultRandomCoin<H>, MerkleTree<H>>(
            proof,
            PublicInputs { data: self.input_data.clone(), result: self.result.clone() },
            &acceptable_options,
        )
    }

    fn verify_with_wrong_inputs(&self, proof: Proof) -> Result<(), VerifierError> {
        let acceptable_options =
            winterfell::AcceptableOptions::OptionSet(vec![proof.options().clone()]);
        let input_string = "WRONG".to_string();
        let input_data = prepare_sha_256_block(&input_string)
            .chunks(16)
            .map(|chunk| {
                let arr: [BaseElement; 16] = chunk
                    .iter()
                    .cloned()
                    .collect::<Vec<BaseElement>>()
                    .try_into()
                    .expect("Chunk should have exactly 16 elements");
                arr
            })
            .collect::<Vec<[BaseElement; 16]>>();

        winterfell::verify::<ExperimentShaAir, H, DefaultRandomCoin<H>, MerkleTree<H>>(
            proof,
            PublicInputs { data: input_data, result: self.result.clone() },
            &acceptable_options,
        )
    }
}
