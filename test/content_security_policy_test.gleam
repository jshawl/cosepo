import content_security_policy.{ContentSecurityPolicy}
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
  let assert Ok(directive1) =
    content_security_policy.new_directive("default-src", [
      "'self'", "https://example.com",
    ])
  let assert Ok(directive2) =
    content_security_policy.new_directive("img-src", ["'none'"])
  ContentSecurityPolicy([directive1, directive2])
  |> content_security_policy.serialize
  |> should.equal("default-src 'self' https://example.com; img-src 'none';")
}

pub fn merge_to_empty_test() {
  let assert Ok(directive1) =
    content_security_policy.new_directive("default-src", ["'none'"])

  ContentSecurityPolicy([])
  |> content_security_policy.merge(directive1)
  |> should.equal(ContentSecurityPolicy([directive1]))
}

pub fn merge_to_new_directive_test() {
  let assert Ok(directive1) =
    content_security_policy.new_directive("default-src", ["'none'"])
  let assert Ok(directive2) =
    content_security_policy.new_directive("img-src", ["'none'"])
  ContentSecurityPolicy([directive1])
  |> content_security_policy.merge(directive2)
  |> should.equal(ContentSecurityPolicy([directive1, directive2]))
}

pub fn merge_to_existing_directive_test() {
  let assert Ok(directive1) =
    content_security_policy.new_directive("default-src", [
      "'self'", "http://example.com",
    ])
  let assert Ok(directive2) =
    content_security_policy.new_directive("default-src", ["https://example.com"])
  let assert Ok(merged_directive) =
    content_security_policy.new_directive("default-src", [
      "'self'", "http://example.com", "https://example.com",
    ])
  ContentSecurityPolicy([directive1])
  |> content_security_policy.merge(directive2)
  |> should.equal(ContentSecurityPolicy([merged_directive]))
}

pub fn set_test() {
  let assert Ok(directive1) =
    content_security_policy.new_directive("default-src", ["'self'"])
  let assert Ok(directive2) =
    content_security_policy.new_directive("default-src", ["'none'"])
  ContentSecurityPolicy([directive1])
  |> content_security_policy.set(directive2)
  |> should.equal(ContentSecurityPolicy([directive2]))
}
