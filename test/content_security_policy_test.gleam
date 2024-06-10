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
    Directive("default-src", ["'self'", "https://example.com"]),
    Directive("img-src", ["'none'"]),
  ])
  |> content_security_policy.serialize
  |> should.equal("default-src 'self' https://example.com; img-src 'none';")
}

pub fn merge_to_empty_test() {
  ContentSecurityPolicy([])
  |> content_security_policy.merge(Directive("default-src", ["'none'"]))
  |> should.equal(ContentSecurityPolicy([Directive("default-src", ["'none'"])]))
}

pub fn merge_to_new_directive_test() {
  ContentSecurityPolicy([Directive("default-src", ["'none'"])])
  |> content_security_policy.merge(Directive("img-src", ["'none'"]))
  |> should.equal(
    ContentSecurityPolicy([
      Directive("default-src", ["'none'"]),
      Directive("img-src", ["'none'"]),
    ]),
  )
}

pub fn merge_to_existing_directive_test() {
  ContentSecurityPolicy([
    Directive("default-src", ["'self'", "http://example.com"]),
  ])
  |> content_security_policy.merge(
    Directive("default-src", ["https://example.com"]),
  )
  |> should.equal(
    ContentSecurityPolicy([
      Directive("default-src", [
        "'self'", "http://example.com", "https://example.com",
      ]),
    ]),
  )
}
