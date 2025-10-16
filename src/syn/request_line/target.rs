use std::net::{Ipv4Addr, Ipv6Addr};

use crate::utils::restore_lifetime;

/// The request-target identifies the target resource upon which to apply
/// the request
pub enum RequestTarget<'src> {
  Origin {
    path: &'src str,
    query: Option<&'src str>,
  },
  Absolute {
    scheme: HttpScheme,
    username: Option<&'src str>,
    password: Option<&'src str>,
    host: Host<'src>,
    port: Option<u16>,
    path: &'src str,
    query: Option<&'src str>,
  },
  Authority {
    host: UriHost<'src>,
    port: u16,
  },
  Asterisk,
}

#[derive(Debug)]
pub enum UriHost<'src> {
  IPv6(Ipv6Addr),
  IPv4(Ipv4Addr),
  Domain(&'src str),
}

impl<'src> RequestTarget<'src> {
  pub fn absolute_from_url(full_url: &'src str, url: &url::Url) -> Self {
    RequestTarget::Absolute {
      scheme: match url.scheme() {
        HTTPS_SCHEME => HttpScheme::HTTPS,
        HTTP_SCHEME => HttpScheme::HTTP,
        _ => unreachable!("exhausted HTTP scheme variants"),
      },
      password: url.password().map(|password| restore_lifetime(full_url, password)),
      username: Some(url.username())
        .filter(|username| username.is_empty())
        .map(|username| restore_lifetime(full_url, username)),
      host: crate::Host::from_url_host(
        full_url,
        url.host().expect("HTTP url with scheme must have a host"),
      ),
      port: url.port(),
      path: restore_lifetime(full_url, url.path()),
      query: url.query().map(|query| restore_lifetime(full_url, query)),
    }
  }
  pub fn origin_from_url(full_url: &'src str, url: &url::Url) -> Self {
    RequestTarget::Origin {
      path: restore_lifetime(full_url, url.path()),
      query: url.query().map(|query| restore_lifetime(full_url, query)),
    }
  }
}

pub enum HttpScheme {
  HTTP,
  HTTPS,
}

pub enum Host<'src> {
  Domain(&'src str),
  Ipv4(Ipv4Addr),
  Ipv6(Ipv6Addr),
}

impl<'src, 'url> Host<'src> {
  pub fn from_url_host(full_url: &'src str, value: url::Host<&'url str>) -> Self {
    match value {
      url::Host::Domain(domain) => Self::Domain(restore_lifetime(full_url, domain)),
      url::Host::Ipv4(ipv4_addr) => Self::Ipv4(ipv4_addr),
      url::Host::Ipv6(ipv6_addr) => Self::Ipv6(ipv6_addr),
    }
  }
}

impl HttpScheme {
  /// is this a secure scheme.
  pub fn is_secure(&self) -> bool {
    matches!(self, Self::HTTPS)
  }
}
