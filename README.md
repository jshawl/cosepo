# cosepo

[![Package Version](https://img.shields.io/hexpm/v/cosepo)](https://hex.pm/packages/cosepo)
[![Hex Docs](https://img.shields.io/badge/hex-docs-ffaff3)](https://hexdocs.pm/cosepo/)

A module for parsing, mutating, and serializing Content-Security-Policy directives.

## Installation

```sh
gleam add cosepo
```

## Usage

```gleam
import cosepo
import cosepo/directive

pub fn main() {
  cosepo.parse("default-src https: 'unsafe-eval' 'unsafe-inline'; object-src 'none'")
  // -> Ok(ContentSecurityPolicy([
  //   Directive("default-src", ["https:", "'unsafe-eval'", "'unsafe-inline'"]),
  //   Directive("object-src", ["'none'"])])
  // )

  let assert Ok(directive1) = directive.new_directive("default-src", ["'none'"])
  let assert Ok(directive2) = directive.new_directive("script-src", ["https://example.com"])
  cosepo.serialize(ContentSecurityPolicy([directive1, directive2]))
  // -> "default-src 'none'; script-src https://example.com;"

  directive.new_directive("an-invalid-directive", [])
  // -> Error("an-invalid-directive is not a valid directive name")
}
```

Further documentation can be found at <https://hexdocs.pm/cosepo>.

## Development

```sh
gleam test  # Run the tests
```
