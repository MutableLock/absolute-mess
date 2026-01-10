use std::ops::Range;

pub struct MessConfig {
    pub garbage_size: Range<usize>,
    pub garbage_amount: Range<usize>,
}
