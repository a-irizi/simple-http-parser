mod target;
mod verb;
mod version;

pub use target::*;
pub use verb::*;

pub struct RequestLine<'src> {
  method: HttpVerb,
  target: RequestTarget<'src>,
}
