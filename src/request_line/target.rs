use std::net::{Ipv4Addr, Ipv6Addr};

use nom::{
  IResult, Parser,
  branch::alt,
  bytes::complete::{tag, take_while, take_while_m_n, take_while1},
  combinator::{peek, recognize},
  error::context,
  multi::separated_list1,
  sequence::{delimited, separated_pair, terminated},
};
use nom_language::error::{VerboseError, VerboseErrorKind};
use url::Url;

use crate::{
  RequestTarget, UriHost, request_line::error::InvalidTargetKind, utils::lexeme_before_sp,
};

const HTTP_SCHEME: &str = "http";
const HTTPS_SCHEME: &str = "https";
const SCHEME_TERMINATOR: &str = "://";

pub(super) fn parse_request_target(
  input: &[u8],
) -> super::Result<'_, (&'_ [u8], RequestTarget<'_>)> {
  // target must not be empty
  if input == b"" {
    return Err(super::Error::InvalidTarget { lexeme: input, kind: InvalidTargetKind::Empty });
  }

  if let Ok(result) = asterisk_host(input) {
    return Ok(result);
  }

  if !input.is_ascii() {
    return Err(super::Error::InvalidTarget {
      lexeme: input,
      kind: InvalidTargetKind::InvalidEncoding,
    });
  }

  let lexeme = str::from_utf8(input).expect("input is ASCII");

  let (rest, target) = if let Some(is_http) = starts_with_http_scheme_with_terminator(input) {
    if is_http {
      let url = Url::parse(lexeme).map_err(|_| super::Error::InvalidTarget {
        lexeme: input,
        kind: InvalidTargetKind::InvalidAbsoluteTarget,
      })?;
      (b"", RequestTarget::absolute_from_url(lexeme, &url))
    } else {
      return Err(super::Error::InvalidTarget {
        lexeme: input,
        kind: InvalidTargetKind::InvalidScheme,
      });
    }
  } else if lexeme.starts_with('/') {
    let url = Url::parse("www.dummy.com").expect("valid url");
    let url = url.join(lexeme).map_err(|_| super::Error::InvalidTarget {
      lexeme: input,
      kind: InvalidTargetKind::InvalidOriginTarget,
    })?;
    (b"", RequestTarget::origin_from_url(lexeme, &url))
  } else {
    let (_, (host, port)) = authority_form_target(input).map_err(|_| {
      super::Error::InvalidTarget { lexeme: input, kind: InvalidTargetKind::InvalidAuthorityTarget }
    })?;

    (b"", RequestTarget::Authority { host, port })
  };

  Ok((rest, target))
}

fn asterisk_host(input: &'_ [u8]) -> IResult<&'_ [u8], RequestTarget<'_>, VerboseError<&'_ [u8]>> {
  tag(b"*".as_slice()).map(|_| RequestTarget::Asterisk).parse(input)
}

/// check if input starts with an HTTP scheme.
///
/// # Returns
/// * `Some(true)` if it starts with an HTTP scheme.
/// * `Some(false)` if it starts with a non-HTTP scheme.
/// * None if it does not start with a scheme.
fn starts_with_http_scheme_with_terminator(input: &[u8]) -> Option<bool> {
  if peek(http_scheme_with_terminator).parse(input).is_ok() {
    return Some(true);
  }

  if peek(valid_scheme_with_terminator).parse(input).is_ok() {
    return Some(false);
  }

  None
}

fn http_scheme_with_terminator(input: &[u8]) -> IResult<&[u8], &[u8], VerboseError<&[u8]>> {
  alt((
    context(
      "insecure HTTP scheme with terminator",
      terminated(
        context("insecure HTTP scheme", tag(HTTP_SCHEME.as_bytes())),
        context("HTTP scheme terminator", tag(SCHEME_TERMINATOR.as_bytes())),
      ),
    ),
    context(
      "secure HTTP scheme with terminator",
      terminated(
        context("secure HTTP scheme", tag(HTTPS_SCHEME.as_bytes())),
        context("HTTP scheme terminator", tag(SCHEME_TERMINATOR.as_bytes())),
      ),
    ),
  ))
  .parse(input)
}

fn valid_scheme_with_terminator(input: &[u8]) -> IResult<&[u8], &[u8], VerboseError<&[u8]>> {
  terminated(
    context("any valid scheme", valid_scheme),
    context("any valid scheme terminator", tag(SCHEME_TERMINATOR.as_bytes())),
  )
  .parse(input)
}

fn valid_scheme(input: &[u8]) -> IResult<&[u8], &[u8], VerboseError<&[u8]>> {
  recognize((
    context(
      "mandatory start with ASCII alphabetic",
      take_while_m_n(1, 1, |b: u8| b.is_ascii_alphabetic()),
    ),
    context(
      "optional trailing ASCII alphabetic, digits, '-', '+' or '.'",
      take_while(|b: u8| matches!(b, b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'+' | b'-' | b'.')),
    ),
  ))
  .parse(input)
}

fn authority_form_target(
  input: &'_ [u8],
) -> IResult<&'_ [u8], (UriHost<'_>, u16), VerboseError<&'_ [u8]>> {
  alt((
    context("IP v6 host and port", ip_v6_host_and_port).map(|(ip, port)| (UriHost::IPv6(ip), port)),
    context("IP v4 host and port", ip_v4_host_and_port).map(|(ip, port)| (UriHost::IPv4(ip), port)),
    context("domain host and port", domain_host_and_port)
      .map(|(domain, port)| (UriHost::Domain(domain), port)),
  ))
  .parse(input)
}

fn ip_v6_host_and_port(input: &[u8]) -> IResult<&[u8], (Ipv6Addr, u16), VerboseError<&[u8]>> {
  separated_pair(
    context("IP v6 host", ip_v6_host),
    context("colon separating IP v6 host and port", tag(b":".as_slice())),
    context("port", nom::character::complete::u16),
  )
  .parse(input)
}
fn ip_v6_host(input: &[u8]) -> IResult<&[u8], Ipv6Addr, VerboseError<&[u8]>> {
  let (rest, parsed) = raw_ip_v6_host(input)?;

  let Ok(parsed_str) = str::from_utf8(parsed) else {
    return Err(nom::Err::Error(VerboseError {
      errors: vec![(parsed, VerboseErrorKind::Context("IP v6 host address as UTF-8"))],
    }));
  };

  let Ok(ip) = parsed_str.parse::<Ipv6Addr>() else {
    return Err(nom::Err::Error(VerboseError {
      errors: vec![(parsed, VerboseErrorKind::Context("IP v6 host address as IPv6Addr"))],
    }));
  };

  Ok((rest, ip))
}

fn raw_ip_v6_host(input: &[u8]) -> IResult<&[u8], &[u8], VerboseError<&[u8]>> {
  delimited(
    context("IP v6 host start delimiter", tag("[")),
    context(
      "IP v6 host address",
      take_while1(|b: u8| b == b':' || b == b'.' || b.is_ascii_hexdigit()),
    ),
    context("IP v6 host end delimiter", tag("]")),
  )
  .parse(input)
}

fn u16_or_colon(input: &[u8]) -> IResult<&[u8], u16, VerboseError<&[u8]>> {
  alt((nom::character::complete::u16, peek(tag(b":".as_slice()).map(|_| 0u16)))).parse(input)
}

fn ip_v4_host_and_port(input: &[u8]) -> IResult<&[u8], (Ipv4Addr, u16), VerboseError<&[u8]>> {
  separated_pair(
    context("IP v4 host", ip_v4_host),
    context("colon separating IP v4 host and port", tag(b":".as_slice())),
    context("port", nom::character::complete::u16),
  )
  .parse(input)
}

fn ip_v4_host(input: &[u8]) -> IResult<&[u8], Ipv4Addr, VerboseError<&[u8]>> {
  let (rest, [a, b, c, d]) = context("raw IP v4", raw_ip_v4_host).parse(input)?;

  Ok((rest, Ipv4Addr::new(a, b, c, d)))
}

fn raw_ip_v4_host(input: &[u8]) -> IResult<&[u8], [u8; 4], VerboseError<&[u8]>> {
  let (rest, (a, _, b, _, c, _, d)) = (
    context("IP v4 first octet", nom::character::complete::u8),
    context("IP v4 first dot", tag(b".".as_slice())),
    context("IP v4 second octet", nom::character::complete::u8),
    context("IP v4 second dot", tag(b".".as_slice())),
    context("IP v4 third octet", nom::character::complete::u8),
    context("IP v4 third dot", tag(b".".as_slice())),
    context("IP v4 fourth octet", nom::character::complete::u8),
  )
    .parse(input)?;

  Ok((rest, [a, b, c, d]))
}

fn domain_host_and_port(input: &[u8]) -> IResult<&[u8], (&str, u16), VerboseError<&[u8]>> {
  separated_pair(
    context("domain host", domain_host),
    context("colon separating domain host and port", tag(b":".as_slice())),
    context("port", nom::character::complete::u16),
  )
  .parse(input)
}

fn domain_host(input: &[u8]) -> IResult<&[u8], &str, VerboseError<&[u8]>> {
  let (rest, parsed) =
    recognize(separated_list1(tag(b".".as_slice()), domain_label)).parse(input)?;

  Ok((
    rest,
    str::from_utf8(parsed)
      .expect("parsed is made of ASCII alphanumeric characters, '.' and '-' characters"),
  ))
}

fn domain_label(input: &[u8]) -> IResult<&[u8], &str, VerboseError<&[u8]>> {
  let (rest, label) = context(
    "domain label valid characters",
    take_while(|b: u8| b == b'-' || b.is_ascii_alphanumeric()),
  )
  .parse(input)?;
  let label =
    str::from_utf8(label).expect("label contains only hyphens and ASCII alphanumeric characters");

  if !(1..=63).contains(&label.len()) {
    return Err(nom::Err::Error(VerboseError {
      errors: vec![(
        input,
        VerboseErrorKind::Context("labels must be 63 characters or less, and must not be empty"),
      )],
    }));
  }

  if !label.starts_with(|c: char| c.is_ascii_alphabetic()) {
    return Err(nom::Err::Error(VerboseError {
      errors: vec![(input, VerboseErrorKind::Context("labels must start with a letter"))],
    }));
  }

  if !label.ends_with(|c: char| c.is_ascii_alphanumeric()) {
    return Err(nom::Err::Error(VerboseError {
      errors: vec![(input, VerboseErrorKind::Context("labels must start with a letter"))],
    }));
  }

  Ok((rest, label))
}

#[cfg(test)]
mod tests {
  use proptest::prelude::ProptestConfig;

  use claims::{assert_err, assert_none, assert_ok, assert_some_eq};
  use const_format::formatcp;
  use proptest::{
    prelude::{Strategy, any},
    prop_compose, prop_oneof, proptest,
  };
  use rstest::rstest;

  use super::{
    HTTP_SCHEME, HTTPS_SCHEME, Ipv4Addr, Ipv6Addr, SCHEME_TERMINATOR, Url, authority_form_target,
    domain_host, domain_host_and_port, http_scheme_with_terminator, ip_v4_host,
    ip_v4_host_and_port, ip_v6_host, ip_v6_host_and_port, starts_with_http_scheme_with_terminator,
    valid_scheme, valid_scheme_with_terminator,
  };

  const VALID_SCHEME_CHARS_REGEX: &str = "[a-zA-Z0-9\\-\\.\\+]";
  const INVALID_SCHEME_CHARS_REGEX: &str = "[^a-zA-Z0-9\\-\\.\\+]";
  const VALID_SCHEME_START_CHAR_REGEX: &str = "[a-zA-Z]";
  const INVALID_SCHEME_START_CHAR_REGEX: &str = "[^a-zA-Z]";

  #[test]
  fn parse_absolute_path() {
    let path = "/where?q=now";
    let dummy_base = "a://anass:irizi@www.example.org:80";
    let uri = Url::parse(&format!("{dummy_base}{path}"));
    let uri = assert_ok!(uri);
    dbg!(uri);
  }

  prop_compose! {
    fn valid_scheme_strategy()
    (scheme in formatcp!("{VALID_SCHEME_START_CHAR_REGEX}{VALID_SCHEME_CHARS_REGEX}*")
      .prop_filter(
        "scheme is HTTP",
        |scheme| !matches!(scheme.as_str(), HTTP_SCHEME | HTTPS_SCHEME)
      )
    ) -> String {
      scheme
    }
  }

  prop_compose! {
    fn invalid_scheme_with_terminator_strategy()(scheme in invalid_scheme_strategy()) -> String {
      format!("{scheme}{SCHEME_TERMINATOR}")
    }
  }

  fn invalid_scheme_strategy() -> impl Strategy<Value = String> {
    prop_oneof![
      invalid_scheme_wrong_character_strategy(),
      invalid_scheme_wrong_start_strategy(),
      invalid_scheme_empty_strategy()
    ]
  }

  fn invalid_scheme_empty_strategy() -> impl Strategy<Value = String> {
    "".boxed()
  }

  prop_compose! {
    fn invalid_scheme_wrong_start_strategy()(start in formatcp!("{INVALID_SCHEME_START_CHAR_REGEX}+"), scheme in valid_scheme_strategy()) -> String {
      format!("{start}{scheme}")
    }
  }

  prop_compose! {
    fn invalid_scheme_wrong_character_strategy()(
      start in formatcp!("{VALID_SCHEME_START_CHAR_REGEX}+{VALID_SCHEME_CHARS_REGEX}*"),
      middle in INVALID_SCHEME_CHARS_REGEX,
      end in formatcp!("{VALID_SCHEME_CHARS_REGEX}*")
    ) -> String {
      format!("{start}{middle}{end}")
    }
  }

  prop_compose! {
    fn valid_scheme_with_terminator_strategy()
    (scheme in valid_scheme_strategy().prop_map(|scheme| format!("{scheme}{SCHEME_TERMINATOR}"))) -> String {
      scheme
    }
  }

  proptest! {
    #[test]
    fn valid_scheme_ok(scheme in valid_scheme_strategy()) {
      let (rest, parsed) = assert_ok!(valid_scheme(scheme.as_bytes()));
      assert_eq!(b"", rest);
      assert_eq!(scheme.as_bytes(), parsed);
    }

    #[test]
    fn valid_scheme_with_terminator_ok(scheme_with_terminator in valid_scheme_with_terminator_strategy()) {
      let (rest, parsed) = assert_ok!(valid_scheme_with_terminator(scheme_with_terminator.as_bytes()));
      assert_eq!(b"", rest);
      let scheme = {
        let scheme_len = scheme_with_terminator.len() - SCHEME_TERMINATOR.len();
        &scheme_with_terminator[..scheme_len]
      };
      assert_eq!(scheme.as_bytes(), parsed);
    }

    #[test]
    fn valid_scheme_with_terminator_err(scheme in invalid_scheme_strategy()) {
      assert_err!(valid_scheme_with_terminator(scheme.as_bytes()));
    }
  }

  #[rstest]
  #[case::secure(HTTPS_SCHEME)]
  #[case::insecure(HTTP_SCHEME)]
  fn http_scheme_with_terminator_ok(#[case] scheme: &'static str) {
    let scheme_with_terminator = format!("{scheme}{SCHEME_TERMINATOR}");
    let (rest, parsed) = assert_ok!(http_scheme_with_terminator(scheme_with_terminator.as_bytes()));
    assert_eq!(b"", rest);
    assert_eq!(scheme.as_bytes(), parsed);
  }

  proptest! {
    #[test]
    fn http_scheme_with_terminator_err_for_valid_non_http_scheme(scheme_with_terminator in valid_scheme_with_terminator_strategy()) {
      assert_err!(http_scheme_with_terminator(scheme_with_terminator.as_bytes()));
    }

    #[test]
    fn http_scheme_with_terminator_err_for_invalid_scheme(scheme_with_terminator in invalid_scheme_with_terminator_strategy()) {
      assert_err!(http_scheme_with_terminator(scheme_with_terminator.as_bytes()));
    }
  }

  #[rstest]
  #[case::secure(format!("{HTTPS_SCHEME}{SCHEME_TERMINATOR}"))]
  #[case::insecure(format!("{HTTP_SCHEME}{SCHEME_TERMINATOR}"))]
  fn starts_with_http_scheme_with_terminator_returns_some_true_for_http_scheme(
    #[case] scheme_with_terminator: String,
  ) {
    assert_some_eq!(
      starts_with_http_scheme_with_terminator(scheme_with_terminator.as_bytes()),
      true
    );
  }

  proptest! {
    #[test]
    fn starts_with_http_scheme_with_terminator_returns_some_false_for_non_http_scheme(
      scheme_with_terminator in valid_scheme_with_terminator_strategy()
    ) {
      assert_some_eq!(
        starts_with_http_scheme_with_terminator(scheme_with_terminator.as_bytes()),
        false
      );
    }
  }

  proptest! {
    #[test]
    fn starts_with_http_scheme_with_terminator_returns_none_for_invalid_scheme(
      scheme_with_terminator in invalid_scheme_with_terminator_strategy()
    ) {
      assert_none!(
        starts_with_http_scheme_with_terminator(scheme_with_terminator.as_bytes())
      );
    }
  }

  #[test]
  fn valid_scheme_is_correct_for_simple_case() {
    let scheme = "a";
    let (rest, parsed) = assert_ok!(valid_scheme(scheme.as_bytes()));
    assert_eq!(b"", rest);
    assert_eq!(b"a".as_slice(), parsed);
  }

  #[test]
  fn valid_scheme_with_terminator_is_correct_for_simple_case() {
    let scheme = "a://";
    let (rest, parsed) = assert_ok!(valid_scheme_with_terminator(scheme.as_bytes()));
    assert_eq!(b"", rest);
    assert_eq!(b"a".as_slice(), parsed);
  }

  #[rstest]
  #[case::uncompressed("[2001:db8:85a3:00:0:8a2e:370:7334]", [0x2001, 0xdb8, 0x85a3, 0x0, 0x0, 0x8a2e, 0x370, 0x7334])]
  #[case::compressed_start("[::7334]", [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x7334])]
  #[case::compressed_middle("[2001:db8::0:8a2e:370:7334]", [0x2001, 0xdb8, 0x0, 0x0, 0x0, 0x8a2e, 0x370, 0x7334])]
  #[case::compressed_end("[2001:db8::]", [0x2001, 0xdb8, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0])]
  #[case::all_zeros("[0:0:0:0:0:0:0:0]", [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0])]
  #[case::all_zeros_compressed("[::]", [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0])]
  #[case::ip_v4_mapped_ip_v6("[::ffff:192.168.1.1]", [0x0, 0x0, 0x0, 0x0, 0x0, 0xffff, 0xc0a8, 0x0101])]
  fn parse_ip_v6_host_ok(#[case] raw_ip: String, #[case] segments: [u16; 8]) {
    let (_, ip) = assert_ok!(ip_v6_host(raw_ip.as_bytes()));
    assert_eq!(segments, ip.segments());
  }

  prop_compose! {
    fn ip_v6_segment_strategy()(segment in 0u16.., pad in 1..=4) -> (u16, String) {
      match pad {
        1 => (segment, format!("{segment:01x}")),
        2=> (segment, format!("{segment:02x}")),
        3=> (segment, format!("{segment:03x}")),
        4=> (segment, format!("{segment:04x}")),
        _ => unreachable!("pad in in 1..4")
      }
    }
  }

  prop_compose! {
    fn ip_v6_uncompressed_addr_strategy()(
      a in ip_v6_segment_strategy(),
      b in ip_v6_segment_strategy(),
      c in ip_v6_segment_strategy(),
      d in ip_v6_segment_strategy(),
      e in ip_v6_segment_strategy(),
      f in ip_v6_segment_strategy(),
      g in ip_v6_segment_strategy(),
      h in ip_v6_segment_strategy(),
    ) -> ([u16; 8], String) {
      (
        [a.0, b.0, c.0, d.0, e.0, f.0, g.0, h.0],
        format!("{}:{}:{}:{}:{}:{}:{}:{}", a.1, b.1, c.1, d.1, e.1, f.1, g.1, h.1)
      )
    }
  }

  proptest! {
    #![proptest_config(ProptestConfig::with_cases(1000))]
    #[test]
    fn ip_v6_host_ok_any_uncompressed(
      (segments, raw_addr) in ip_v6_uncompressed_addr_strategy()
        .prop_map(|(segments, addr)| (segments, format!("[{addr}]")))
      ) {
      let (_, parsed) = assert_ok!(ip_v6_host(raw_addr.as_bytes()));
      assert_eq!(segments, parsed.segments());
    }
  }

  prop_compose! {
    fn ip_v6_comporessed_start_addr_strategy()
      (segments in proptest::collection::vec(ip_v6_segment_strategy(), 1usize..=7))
      -> ([u16; 8], String)
    {
      let (segments, segments_str): (Vec<_>, Vec<_>) = segments.into_iter().unzip();

      let mut full_segments = [0u16; 8];
      let start_index = 8 - segments.len();
      full_segments[start_index..].copy_from_slice(&segments);

      (full_segments, format!("::{}", segments_str.join(":")))
    }
  }

  proptest! {
    #![proptest_config(ProptestConfig::with_cases(1000))]
    #[test]
    fn ip_v6_host_ok_any_compressed_start(
      (segments, raw_addr) in ip_v6_comporessed_start_addr_strategy()
        .prop_map(|(segments, addr)| (segments, format!("[{addr}]")))) {
        let (_, parsed) = assert_ok!(ip_v6_host(raw_addr.as_bytes()));
        assert_eq!(segments, parsed.segments());
    }
  }

  prop_compose! {
    fn ip_v6_comporessed_end_addr_strategy()
      (segments in proptest::collection::vec(ip_v6_segment_strategy(), 1usize..=7))
      -> ([u16; 8], String)
    {
      let (segments, segments_str): (Vec<_>, Vec<_>) = segments.into_iter().unzip();

      let mut full_segments = [0u16; 8];
      full_segments[..segments.len()].copy_from_slice(&segments);

      (full_segments, format!("{}::", segments_str.join(":")))
    }
  }

  proptest! {
    #![proptest_config(ProptestConfig::with_cases(1000))]
    #[test]
    fn ip_v6_host_ok_any_compressed_end(
      (segments, raw_addr) in ip_v6_comporessed_end_addr_strategy()
        .prop_map(|(segments, addr)| (segments, format!("[{addr}]")))) {
        let (_, parsed) = assert_ok!(ip_v6_host(raw_addr.as_bytes()));
        assert_eq!(segments, parsed.segments());
    }
  }

  prop_compose! {
    fn ip_v4_addr_strategy()(a in any::<u8>(), b in any::<u8>(), c in any::<u8>(), d in any::<u8>()) -> ([u8; 4], String) {
      ([a, b, c, d], format!("{a}.{b}.{c}.{d}"))
    }
  }

  fn combine_u8_into_u16(high: u8, low: u8) -> u16 {
    let high = u16::from(high) << 8;
    let low = u16::from(low);
    high | low
  }

  fn combine_8_u16_into_u128(bits: [u16; 8]) -> u128 {
    let mut result: u128 = 0;
    for (shift, bits) in (0..8).map(|i| i * 16).rev().zip(bits) {
      result |= u128::from(bits) << shift
    }

    result
  }

  fn combine_4_u8_into_u32(bits: [u8; 4]) -> u32 {
    let mut result: u32 = 0;
    for (shift, bits) in (0..4).map(|i| i * 8).rev().zip(bits) {
      result |= u32::from(bits) << shift
    }

    result
  }

  prop_compose! {
    fn ip_v6_mapped_ip_v4_addr_strategy()
      ((octets, ip_v4) in ip_v4_addr_strategy()) -> ([u16; 8], String) {
      let mut segments = [0u16; 8];
      segments[5] = 0xFFFF;
      segments[6] = combine_u8_into_u16(octets[0], octets[1]);
      segments[7] = combine_u8_into_u16(octets[2], octets[3]);
      let ip_v6 = format!("::ffff:{ip_v4}");

      (segments, ip_v6)
    }
  }

  proptest! {
    #![proptest_config(ProptestConfig::with_cases(1000))]
    #[test]
    fn ip_v6_host_ok_any_mapped_ip_v4(
      (segments, raw_addr) in ip_v6_mapped_ip_v4_addr_strategy()
        .prop_map(|(segments, addr)| (segments, format!("[{addr}]")))) {
        let (_, parsed) = assert_ok!(ip_v6_host(raw_addr.as_bytes()));
        assert_eq!(segments, parsed.segments());
    }
  }

  prop_compose! {
    fn ip_v6_comporessed_middle_addr_strategy()
      (start_segment_count in 1..=6usize)
      (
        start_segments in proptest::collection::vec(ip_v6_segment_strategy(), start_segment_count),
        end_segments in proptest::collection::vec(ip_v6_segment_strategy(), 1..=7 - start_segment_count)
      )
      -> ([u16; 8], String)
    {
      let (start_segments, start_segments_str): (Vec<_>, Vec<_>) = start_segments.into_iter().unzip();
      let (end_segments, end_segments_str): (Vec<_>, Vec<_>) = end_segments.into_iter().unzip();

      let mut full_segments = [0u16; 8];
      full_segments[..start_segments.len()].copy_from_slice(&start_segments);
      let end_segments_index = 8 - end_segments.len();
      full_segments[end_segments_index..].copy_from_slice(&end_segments);


      (full_segments, format!("{}::{}", start_segments_str.join(":"), end_segments_str.join(":")))
    }
  }

  proptest! {
    #![proptest_config(ProptestConfig::with_cases(1000))]
    #[test]
    fn ip_v6_host_ok_any_compressed_middle(
      (segments, raw_addr) in ip_v6_comporessed_middle_addr_strategy()
        .prop_map(|(segments, addr)| (segments, format!("[{addr}]")))) {
        let (_, parsed) = assert_ok!(ip_v6_host(raw_addr.as_bytes()));
        assert_eq!(segments, parsed.segments());
    }
  }

  fn ip_v6_addr_strategy() -> impl Strategy<Value = ([u16; 8], String)> {
    prop_oneof![
      ip_v6_uncompressed_addr_strategy(),
      ip_v6_comporessed_start_addr_strategy(),
      ip_v6_comporessed_middle_addr_strategy(),
      ip_v6_comporessed_end_addr_strategy(),
      ip_v6_mapped_ip_v4_addr_strategy(),
    ]
  }

  proptest! {
    #![proptest_config(ProptestConfig::with_cases(4000))]
    #[test]
    fn ip_v6_host_ok_all(
      (segments, raw_addr) in ip_v6_addr_strategy()
        .prop_map(|(segments, addr)| (segments, format!("[{addr}]")))) {
        let (_, parsed) = assert_ok!(ip_v6_host(raw_addr.as_bytes()));
        assert_eq!(segments, parsed.segments());
    }
  }

  proptest! {
    #![proptest_config(ProptestConfig::with_cases(4000))]
    #[test]
    fn ip_v6_host_err_all(input in ".*") {
      assert_err!(ip_v6_host(input.as_bytes()));
    }
  }

  prop_compose! {
    fn ip_v6_host_and_port_strategy()
      (
        host in ip_v6_addr_strategy().prop_map(|(segments, addr)| (segments, format!("[{addr}]"))),
        port in any::<u16>()
      ) -> ([u16; 8], u16, String) {
      (host.0, port, format!("{host}:{port}", host = host.1, port = port))
    }
  }

  proptest! {
    #![proptest_config(ProptestConfig::with_cases(1000))]
    #[test]
    fn ip_v6_host_and_port_ok_all((segments, port, authority) in ip_v6_host_and_port_strategy()) {
      let (_, parsed) = assert_ok!(ip_v6_host_and_port(authority.as_bytes()));
      assert_eq!(segments, parsed.0.segments());
      assert_eq!(port, parsed.1);
    }
  }

  proptest! {
    #![proptest_config(ProptestConfig::with_cases(1000))]
    #[test]
    fn ip_v6_host_and_port_err_all(input in ".*") {
      assert_err!(ip_v6_host_and_port(input.as_bytes()));
    }
  }

  proptest! {
    #[test]
    fn ip_v4_host_ok_all((octets, ip) in ip_v4_addr_strategy()) {
      let (_, parsed) = assert_ok!(ip_v4_host(ip.as_bytes()));
      assert_eq!(octets, parsed.octets());
    }
  }

  proptest! {
    #[test]
    fn ip_v4_host_err_all(input in ".*") {
       assert_err!(ip_v4_host(input.as_bytes()));
    }
  }

  prop_compose! {
    fn ip_v4_host_and_port_strategy()
      (
        host in ip_v4_addr_strategy(),
        port in any::<u16>()
      ) -> ([u8; 4], u16, String) {
      (host.0, port, format!("{host}:{port}", host = host.1, port = port))
    }
  }

  proptest! {
    #[test]
    fn ip_v4_host_and_port_ok_all((octets, port, ip) in ip_v4_host_and_port_strategy()) {
      let (_, parsed) = assert_ok!(ip_v4_host_and_port(ip.as_bytes()));
      assert_eq!(octets, parsed.0.octets());
      assert_eq!(port, parsed.1);
    }
  }

  proptest! {
    #[test]
    fn ip_v4_host_and_port_err_all(input in ".*") {
       assert_err!(ip_v4_host_and_port(input.as_bytes()));
    }
  }

  prop_compose! {
    fn alphanumeric_and_hyphen_strategy()(i in "[a-zA-Z0-9\\-]{0,61}") -> String {
      i
    }
  }

  prop_compose! {
    fn alphanumeric_and_hyphen_ends_with_alphanumeric_strategy()
      (anh in alphanumeric_and_hyphen_strategy(), an in "[a-zA-Z0-9]{1}") -> String{
      format!("{anh}{an}")
    }
  }

  prop_compose! {
    fn optional_alphanumeric_strategy()(an in "[a-zA-Z0-9]{0,1}") -> String {
      an
    }
  }

  fn domain_host_label_remainder_strategy() -> impl Strategy<Value = String> {
    prop_oneof![
      optional_alphanumeric_strategy(),
      alphanumeric_and_hyphen_ends_with_alphanumeric_strategy()
    ]
  }

  prop_compose! {
    fn domain_host_label_strategy()(a in "[a-zA-Z]", remainder in domain_host_label_remainder_strategy()) -> String {
      format!("{a}{remainder}")
    }
  }
  prop_compose! {
    fn domain_host_strategy(max_label_count: usize)
      (labels in proptest::collection::vec(domain_host_label_strategy(), max_label_count)) -> String {
      labels.join(".")
    }
  }

  prop_compose! {
    fn invalid_domain_host_strategy()(input in "\\S*".prop_filter("valid domain host label", |s| {
      !s.starts_with(|c: char| c.is_ascii_alphabetic()) &&
      (s.len() > 63
        || !s.ends_with(|c: char| c.is_ascii_alphanumeric())
        || s.contains(|c: char| !c.is_ascii_alphanumeric() && c != '-' && c != '.'))
        }
    )) -> String {
      input
    }
  }

  proptest! {
    #[test]
    fn domain_host_ok(host in domain_host_strategy(12)) {
      let (rest, parsed) = assert_ok!(domain_host(host.as_bytes()));
      assert_eq!(host, parsed);
      assert!(rest.is_empty());
    }
  }

  proptest! {
    #[test]
    fn domain_host_err(input in invalid_domain_host_strategy()) {
      assert_err!(domain_host(input.as_bytes()));
    }
  }

  prop_compose! {
    fn domain_host_and_port_strategy(max_label_count: usize)
      (host in domain_host_strategy(max_label_count), port in any::<u16>()) -> (String, u16, String) {
      let host_and_port = format!("{host}:{port}");
      (host, port, host_and_port)
    }
  }

  proptest! {
    #[test]
    fn domain_host_and_port_ok((host, port, host_and_port) in domain_host_and_port_strategy(12)) {
      let (rest, parsed) = assert_ok!(domain_host_and_port(host_and_port.as_bytes()));
      assert_eq!((host.as_str(), port), parsed);
      assert!(rest.is_empty());
    }
  }

  #[derive(Debug)]
  struct AuthorityForm {
    host: UriHost,
    port: u16,
    repr: String,
  }

  #[derive(Debug)]
  enum UriHost {
    IPv6(Ipv6Addr),
    IPv4(Ipv4Addr),
    Domain(String),
  }

  fn authority_form_strategy(max_label_count: usize) -> impl Strategy<Value = AuthorityForm> {
    prop_oneof![
      ip_v6_host_and_port_strategy().prop_map(|(segments, port, repr)| {
        AuthorityForm {
          host: UriHost::IPv6(Ipv6Addr::from_bits(combine_8_u16_into_u128(segments))),
          port,
          repr,
        }
      }),
      ip_v4_host_and_port_strategy().prop_map(|(octets, port, repr)| AuthorityForm {
        host: UriHost::IPv4(Ipv4Addr::from_bits(combine_4_u8_into_u32(octets))),
        port,
        repr
      }),
      domain_host_and_port_strategy(max_label_count).prop_map(|(domain, port, repr)| {
        AuthorityForm { host: UriHost::Domain(domain), port, repr }
      })
    ]
  }

  proptest! {
    #![proptest_config(ProptestConfig::with_cases(1000))]
    #[test]
    fn authority_form_target_ok(AuthorityForm {host, port, repr} in authority_form_strategy(12)) {
      println!("{repr}");
      let (rest, (parsed_host, parsed_port)) = assert_ok!(authority_form_target(repr.as_bytes()));
      assert!(rest.is_empty());
      assert_eq!(port, parsed_port);
      match (&parsed_host, &host) {
        (crate::UriHost::IPv6(parsed_ipv6_addr), UriHost::IPv6(ipv6_addr)) => assert_eq!(ipv6_addr, parsed_ipv6_addr),
        (crate::UriHost::IPv4(parsed_ipv4_addr), UriHost::IPv4(ipv4_addr)) => assert_eq!(ipv4_addr, parsed_ipv4_addr),
        (crate::UriHost::Domain(parsed_domain), UriHost::Domain(domain)) => assert_eq!(domain, parsed_domain),
        _ => panic!("{host:?} {parsed_host:?} do not match"),
      }
    }
  }
}
