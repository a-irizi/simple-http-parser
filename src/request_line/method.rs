use nom::{IResult, Parser, branch::alt, bytes::complete::tag, error::context};
use nom_language::error::VerboseError;

use crate::{HttpVerb, utils::lexeme_before_sp};

const GET_TAG: &[u8] = b"GET";
const HEAD_TAG: &[u8] = b"HEAD";
const POST_TAG: &[u8] = b"POST";
const PUT_TAG: &[u8] = b"PUT";
const DELETE_TAG: &[u8] = b"DELETE";
const CONNECT_TAG: &[u8] = b"CONNECT";
const OPTIONS_TAG: &[u8] = b"OPTIONS";
const TRACE_TAG: &[u8] = b"TRACE";
const PATCH_TAG: &[u8] = b"PATCH";

// parses an HTTP method lexeme.
pub fn parse_http_method(input: &[u8]) -> super::Result<'_, (&[u8], HttpVerb)> {
  match parse_http_method_inner(input) {
    Ok((rest, method)) => Ok((rest, method)),
    Err(_) => {
      let (_, before_sp) = lexeme_before_sp(input).unwrap_or((b"", input));
      Err(super::Error::InvalidMethod(before_sp))
    }
  }
}

pub fn parse_http_method_inner(input: &[u8]) -> IResult<&[u8], HttpVerb, VerboseError<&[u8]>> {
  context(
    "request verb",
    alt((
      context("request verb GET.", tag(GET_TAG).map(|_| HttpVerb::Get)),
      context("request verb HEAD.", tag(HEAD_TAG).map(|_| HttpVerb::Head)),
      context("request verb POST.", tag(POST_TAG).map(|_| HttpVerb::Post)),
      context("request verb PUT.", tag(PUT_TAG).map(|_| HttpVerb::Put)),
      context("request verb DELETE.", tag(DELETE_TAG).map(|_| HttpVerb::Delete)),
      context("request verb CONNECT.", tag(CONNECT_TAG).map(|_| HttpVerb::Connect)),
      context("request verb OPTIONS.", tag(OPTIONS_TAG).map(|_| HttpVerb::Options)),
      context("request verb TRACE.", tag(TRACE_TAG).map(|_| HttpVerb::Trace)),
      context("request verb PATCH.", tag(PATCH_TAG).map(|_| HttpVerb::Patch)),
    )),
  )
  .parse(input)
}

#[cfg(test)]
mod tests {
  use claims::{assert_err, assert_matches, assert_ok};
  use nom_language::error::VerboseError;
  use proptest::{
    prelude::{Just, Strategy},
    prop_compose, prop_oneof, proptest,
  };

  use super::*;

  fn http_method_strategy() -> impl Strategy<Value = HttpVerb> {
    prop_oneof![
      Just(HttpVerb::Get),
      Just(HttpVerb::Head),
      Just(HttpVerb::Post),
      Just(HttpVerb::Put),
      Just(HttpVerb::Delete),
      Just(HttpVerb::Options),
      Just(HttpVerb::Patch)
    ]
  }

  prop_compose! {
    fn http_method_lexeme_pair()(pair in http_method_strategy().prop_map(|method|{
          let lexeme = match method {
                HttpVerb::Get => GET_TAG,
                HttpVerb::Head => HEAD_TAG,
                HttpVerb::Post => POST_TAG,
                HttpVerb::Put => PUT_TAG,
                HttpVerb::Delete => DELETE_TAG,
                HttpVerb::Connect => CONNECT_TAG,
                HttpVerb::Options => OPTIONS_TAG,
                HttpVerb::Trace => TRACE_TAG,
                HttpVerb::Patch => PATCH_TAG,
              };
          (method, lexeme)
    })) -> (HttpVerb, &'static [u8]) {
      pair
    }
  }

  prop_compose! {
    fn non_http_method_lexeme()(
      lexeme in "\\PC*"
      .prop_filter(
        "input is a valid HTTP method",
        |value| !matches!(
          value.as_bytes(),
          GET_TAG
          | HEAD_TAG
          | POST_TAG
          | PUT_TAG
          | DELETE_TAG
          | CONNECT_TAG
          | OPTIONS_TAG
          | TRACE_TAG
          | PATCH_TAG
        )
      )
    ) -> String {
      lexeme
    }
  }

  proptest! {
    #[test]
    fn it_parses_valid_request_method_correctly((method, lexeme) in http_method_lexeme_pair()) {
      let (rest, parsed) = assert_ok!(parse_http_method_inner(lexeme));
      assert!(rest.is_empty());
      assert_eq!(method, parsed);
    }

    #[test]
    fn it_fails_to_parse_invalid_request_method(lexeme in non_http_method_lexeme()) {
      let err = assert_err!(parse_http_method_inner(lexeme.as_bytes()));
      assert_matches!(err, nom::Err::Error(VerboseError { .. }));
    }
  }
}
