import content_security_policy.{ContentSecurityPolicy, Directive}
import gleam/io
import gleam/list
import gleam/result
import gleeunit
import gleeunit/should

pub fn main() {
  gleeunit.main()
}

pub fn parse_test() {
  let csp =
    content_security_policy.parse("default-src 'self' https://example.com")
  csp
  |> should.be_ok
  let valid_csp = result.unwrap(csp, ContentSecurityPolicy(directives: []))
  list.length(valid_csp.directives)
  |> should.equal(1)
}

pub fn parse_error_test() {
  content_security_policy.parse("🙈")
  |> should.be_error
}

pub fn serialize_test() {
  ContentSecurityPolicy([
    Directive(name: "default-src", value: ["'self'", "https://example.com"]),
    Directive(name: "img-src", value: ["'none'"]),
  ])
  |> content_security_policy.serialize
  |> should.equal("default-src 'self' https://example.com; img-src 'none';")
}
