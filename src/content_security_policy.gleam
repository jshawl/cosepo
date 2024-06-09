import gleam/io
import gleam/list
import gleam/string

pub type ContentSecurityPolicy {
  ContentSecurityPolicy(directive_set: List(Directive))
}

pub type Directive {
  Directive(name: String, value: List(String))
}

/// https://www.w3.org/TR/CSP3/#parse-serialized-policy
pub fn parse(serialized_csp: String) {
  let csp = Ok(ContentSecurityPolicy(directive_set: []))
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
          let new_directive_set =
            list.append(valid_csp.directive_set, [
              Directive(name: name, value: value),
            ])
          Ok(ContentSecurityPolicy(directive_set: new_directive_set))
        }
      }
    }
  }
}
