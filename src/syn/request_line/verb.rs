/// The HTTP request method is the primary source of request semantics;
/// it indicates the purpose for which the client has made this request
/// and what is expected by the client as a successful result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HttpVerb {
  /// Transfer a current representation of the target resource.
  Get,
  /// Same as GET, but do not transfer the response content.
  Head,
  /// Perform resource-specific processing on the request content.
  Post,
  /// Replace all current representations of the target resource with the
  /// request content.
  Put,
  /// Remove all current representations of the target resource.
  Delete,
  /// Establish a tunnel to the server identified by the target resource.
  Connect,
  /// Describe the communication options for the target resource.
  Options,
  /// Perform a message loop-back test along the path to the target
  /// resource.
  Trace,
  /// The PATCH method applies partial modifications to a resource.
  Patch,
}
