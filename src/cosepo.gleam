import cosepo/directive.{type Directive, get_name, get_value, new_directive}
import gleam/list
import gleam/string

pub type ContentSecurityPolicy {
  ContentSecurityPolicy(directives: List(Directive))
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
              let assert Ok(directive) =
                new_directive("upgrade-insecure-requests", [])
              Ok(merge(valid_csp, directive))
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
      <> get_name(directive)
      <> list.fold(get_value(directive), "", fn(serialized_directive, value) {
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
  get_name(directive) == name
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
  case find_directive_by_name(content_security_policy, get_name(directive)) {
    Error(_) -> {
      list.append(content_security_policy.directives, [directive])
    }
    Ok(existing_directive) -> {
      let value =
        list.append(get_value(existing_directive), get_value(directive))
      let assert Ok(next) = new_directive(get_name(directive), value)
      [next]
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
  case find_directive_by_name(content_security_policy, get_name(directive)) {
    Error(_) -> {
      list.append(content_security_policy.directives, [directive])
    }
    Ok(existing_directive) -> {
      let assert Ok(next) =
        new_directive(get_name(existing_directive), get_value(directive))
      [next]
    }
  }
  |> ContentSecurityPolicy
}
