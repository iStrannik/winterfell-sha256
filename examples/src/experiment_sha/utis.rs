use super::BaseElement;
use super::FieldElement;

pub fn extend_sha256_block(data: Vec<BaseElement>) -> Vec<BaseElement> {
    let mut w = data.iter().map(|e| element_to_u32(*e)).collect::<Vec<_>>();
    w.append(&mut vec![0u32; 48]);

    // Заполнение оставшихся 48 слов
    for i in 16..64 {
        let s0 = (w[i - 15].rotate_right(7)) ^ (w[i - 15].rotate_right(18)) ^ (w[i - 15] >> 3);
        let s1 = (w[i - 2].rotate_right(17)) ^ (w[i - 2].rotate_right(19)) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
    }
    w.iter().map(|e| BaseElement::new(*e as u128)).collect()
}

pub fn prepare_sha_256_block(s: &String) -> Vec<BaseElement> {
    let mut m = s.as_bytes().to_vec();
    m.push(0x80);
    if 64 - m.len() % 64 < 8 {
        m.append(&mut vec![0u8; 64 - m.len() % 64])
    }
    m.append(&mut vec![0u8; 64 - m.len() % 64 - 8]);
    m.append(&mut (s.as_bytes().len() as u64 * 8).to_be_bytes().to_vec());
    println!("Len of final block is {:?} bytes", m.len());
    bytes_to_elements(&m)
}

pub fn bytes_to_elements(s: &[u8]) -> Vec<BaseElement> {
    s.chunks_exact(4).map(|chunk| BaseElement::new(u32::from_be_bytes(chunk.try_into().unwrap()) as u128)).collect()
}

pub fn string_to_elements(s: &String) -> Vec<BaseElement> {
    bytes_to_elements(s.as_bytes())
}

pub fn element_to_u32<E: FieldElement + From<BaseElement>>(e: E) -> u32 {
    u32::from_le_bytes(e.to_bytes()[..4].try_into().unwrap())
}

pub fn elements_to_string(v: Vec<BaseElement>) -> String {
    String::from_utf8(v.iter().map(|e| element_to_u32(*e).to_le_bytes()).collect::<Vec<_>>().concat()).unwrap()
}

pub fn get_iv() -> [BaseElement; 8] {
    [
        0x6a09e667u32, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ].map(|u| BaseElement::new(u as u128)).to_vec().try_into().unwrap()
}

pub fn transpose<const M: usize, const N: usize>(input: [[BaseElement; N]; M]) -> [[BaseElement; M]; N] {
    let mut output = [[input[0][0]; M]; N];
    for i in 0..N {
        for j in 0..M {
            output[i][j] = input[j][i];
        }
    }
    println!("{:?}", output);
    output
}

pub fn transpose_vec(input: Vec<[BaseElement; 2]>) -> [Vec<BaseElement>; 2] {
    let mut output = [Vec::new(), Vec::new()];
    for row in input {
        output[0].push(row[0]);
        output[1].push(row[1]);
    }
    output
}

pub fn extract_hash(state: &[BaseElement]) -> Vec<u8> {
    let mut hash = Vec::with_capacity(32);
    for i in 0..8 {
        hash.extend_from_slice(&element_to_u32(state[64 + i]).to_be_bytes());
    }
    hash
}
