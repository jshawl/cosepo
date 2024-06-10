import gleam/list
import gleam/string

pub type ContentSecurityPolicy {
  ContentSecurityPolicy(directives: List(Directive))
}

const valid_directive_names = [
  "base-uri", "child-src", "connect-src", "default-src", "font-src",
  "form-action", "frame-ancestors", "frame-src", "img-src", "manifest-src",
  "media-src", "object-src", "script-src", "script-src-attr", "script-src-elem",
  "style-src", "style-src-attr", "style-src-elem", "upgrade-insecure-requests",
  "worker-src",
]

/// Use `.new_directive(name: String, value: String)` to construct a `Directive` 
pub opaque type Directive {
  Directive(name: String, value: List(String))
}

/// Creates a new `Directive`, validating the directive name
/// and values.
///
/// ## Example
/// ```gleam
/// new_directive("default-src", ["'self'"])
/// // -> Ok(Directive(name: "default-src", value: ["'self'"]))
///
/// new_directive("invalid-directive", [])
/// // -> Error("invalid-directive is not a valid directive name")
/// ```
pub fn new_directive(
  name name: String,
  value value: List(String),
) -> Result(Directive, String) {
  case list.find(valid_directive_names, fn(x) { x == name }) {
    Error(_) -> Error(name <> " is not a valid directive name")
    Ok(_) -> {
      case name {
        "upgrade-insecure-requests" -> {
          case value {
            [] -> Ok(Directive(name, value))
            _ ->
              Error("unexpected values for upgrade-insecure-requests directive")
          }
        }
        _ -> Ok(Directive(name, value))
      }
    }
  }
}

/// Parses a serialized content security policy string
/// https://www.w3.org/TR/CSP3/#parse-serialized-policy
/// 
/// ## Example
/// ```gleam
/// parse("default-src 'self'")
/// // -> Ok(ContentSecurityPolicy(directives: [
/// //      Directive(name: "default-src", value: ["'self'"]),
/// //    ]))
/// 
/// parse("invalid-directive 'self'")
/// // -> Error("invalid-directive is not a valid directive name")
/// ```
pub fn parse(serialized_csp: String) -> Result(ContentSecurityPolicy, String) {
  let csp = Ok(ContentSecurityPolicy(directives: []))
  use accumulator, directive <- list.fold(
    string.split(serialized_csp, ";"),
    csp,
  )
  case accumulator {
    Error(e) -> Error(e)
    Ok(valid_csp) -> {
      let trimmed_directive = string.trim(directive)
      case string.split(trimmed_directive, " ") {
        [] -> Error("Nothing to parse!")
        [name] -> {
          case name {
            "upgrade-insecure-requests" -> {
              Ok(merge(valid_csp, Directive("upgrade-insecure-requests", [])))
            }
            "" -> Ok(valid_csp)
            _ -> Error("missing directive values for " <> trimmed_directive)
          }
        }
        [name, ..value] -> {
          case new_directive(name: string.lowercase(name), value: value) {
            Error(e) -> Error(e)
            Ok(new_directive) -> {
              Ok(merge(valid_csp, new_directive))
            }
          }
        }
      }
    }
  }
}

/// Generates a serialized string, suitable for the Content-Security-Policy
/// HTTP header.
/// 
/// ## Example
/// ```gleam
/// let assert Ok(content_security_policy) = parse("default-src 'self';")
/// content_security_policy |> serialize
/// // -> "default-src 'self';"
/// ```
pub fn serialize(content_security_policy: ContentSecurityPolicy) -> String {
  list.fold(
    content_security_policy.directives,
    "",
    fn(serialized_csp, directive) {
      serialized_csp
      <> directive.name
      <> list.fold(directive.value, "", fn(serialized_directive, value) {
        serialized_directive <> " " <> value
      })
      <> "; "
    },
  )
  |> string.trim
}

fn find_directive_by_name(
  content_security_policy: ContentSecurityPolicy,
  name: String,
) {
  use directive <- list.find(content_security_policy.directives)
  directive.name == name
}

/// Merges a Directive with an existing ContentSecurityPolicy
/// 
/// ## Example
/// ```gleam
/// let existing_csp = parse("default-src 'self';")
/// let assert Ok(directive) = new_directive("default-src", ["https://example.com/"])
/// merge(existing_csp, directive)
/// // -> ContentSecurityPolicy([
/// //   Directive("default-src", ["'self'", "https://example.com"])
/// // ])
/// ```
pub fn merge(
  content_security_policy: ContentSecurityPolicy,
  directive: Directive,
) -> ContentSecurityPolicy {
  case find_directive_by_name(content_security_policy, directive.name) {
    Error(_) -> {
      list.append(content_security_policy.directives, [directive])
    }
    Ok(existing_directive) -> {
      let value = list.append(existing_directive.value, directive.value)
      [Directive(..directive, value: value)]
    }
  }
  |> ContentSecurityPolicy
}

/// Modifies a ContentSecurityPolicy, overwriting a previous directive, if present
/// 
/// ## Example
/// ```gleam
/// let assert Ok(content_security_policy) = parse("default-src 'self'")
/// let assert Ok(directive) = new_directive("default-src", ["'none'"])
/// set(content_security_policy, directive) |> serialize
/// // -> "default-src 'none';"
/// ```
pub fn set(content_security_policy: ContentSecurityPolicy, directive: Directive) {
  case find_directive_by_name(content_security_policy, directive.name) {
    Error(_) -> {
      list.append(content_security_policy.directives, [directive])
    }
    Ok(existing_directive) -> {
      [Directive(..existing_directive, value: directive.value)]
    }
  }
  |> ContentSecurityPolicy
}
