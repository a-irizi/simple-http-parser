use thiserror::Error;

pub type Result<'src, T> = core::result::Result<T, Error<'src>>;

#[derive(Debug, Error)]
pub enum Error<'src> {
  #[error("invalid request method")]
  InvalidMethod(&'src [u8]),
  #[error("invalid request target")]
  InvalidTarget { lexeme: &'src [u8], kind: InvalidTargetKind },
}

#[derive(Debug)]
pub enum InvalidTargetKind {
  Empty,
  InvalidEncoding,
  InvalidAbsoluteTarget,
  InvalidOriginTarget,
  InvalidAuthorityTarget,
  InvalidScheme,
}
