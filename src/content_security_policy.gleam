import gleam/io
import gleam/list
import gleam/string

pub type ContentSecurityPolicy {
  ContentSecurityPolicy(directives: List(Directive))
}

pub type Directive {
  Directive(name: String, value: List(String))
}

/// Parses a serialized content security policy string
/// https://www.w3.org/TR/CSP3/#parse-serialized-policy
/// 
/// ## Example
/// ```gleam
/// parse("default-src 'self'")
/// // -> ContentSecurityPolicy(directives: [
///         Directive(name: "default-src", value: ["'self'"]),
///       ])
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
        [] | [_] -> Error("Invalid directive: " <> trimmed_directive)
        [name, ..value] -> {
          let name = string.lowercase(name)
          let new_directives =
            list.append(valid_csp.directives, [
              Directive(name: name, value: value),
            ])
          Ok(ContentSecurityPolicy(directives: new_directives))
        }
      }
    }
  }
}

/// Generates a serialized string, suitable for the Content-Security-Policy
/// HTTP header
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
