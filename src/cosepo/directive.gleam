import gleam/list

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

/// Returns the name of a directive
/// 
/// ## Example
/// ```gleam
/// Directive("default-src", ["'none'"])
/// |> get_name // -> "default-src"
/// ```
pub fn get_name(directive: Directive) {
  directive.name
}

/// Returns the value of a directive
/// 
/// ## Example
/// ```gleam
/// Directive("default-src", ["'none'"])
/// |> get_value // -> ["'none'"]
/// ```
pub fn get_value(directive: Directive) {
  directive.value
}
