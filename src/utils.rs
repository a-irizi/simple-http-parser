use nom::{IResult, Parser, bytes::complete::take_while};

pub fn is_sp(b: u8) -> bool {
  matches!(b, b' ' | b'\t' | b'\x0B' | b'\x0C' | b'\n')
}

pub fn lexeme_before_sp(input: &[u8]) -> IResult<&[u8], &[u8]> {
  take_while(|c: u8| !is_sp(c)).parse(input)
}

/// # Arguments
/// * `source`: source string slice.
/// * `slice`: slice of the source string slice.
///
/// # Returns
/// returns a string slice with the same lifetime as the first slice.
///
/// # Panics
/// panics if the second argument is not a slice of the first argument.
pub fn restore_lifetime<'src, 'b>(source: &'src str, slice: &'b str) -> &'src str {
  let source_start_ptr = source.as_ptr() as usize;
  let source_end_ptr = source_start_ptr + source.len();

  let slice_start_ptr = slice.as_ptr() as usize;
  let slice_end_ptr = slice_start_ptr + slice.len();

  assert!(source_start_ptr <= slice_start_ptr);
  assert!(slice_end_ptr <= source_end_ptr);

  let slice_start_index = slice_start_ptr - source_start_ptr;
  let slice_end_index = slice_start_index + slice.len();

  &source[slice_start_index..slice_end_index]
}
