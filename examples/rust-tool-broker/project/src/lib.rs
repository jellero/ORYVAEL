#![forbid(unsafe_code)]

pub fn classify(input: &[u8]) -> usize {
    let mut accumulator = 0usize;
    for &byte in input {
        accumulator = accumulator.rotate_left(5) ^ usize::from(byte);
    }
    accumulator % 17
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classification_is_bounded() {
        assert!(classify(b"oryvael") < 17);
    }
}
