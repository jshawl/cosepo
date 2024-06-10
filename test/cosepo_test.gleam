import cosepo.{ContentSecurityPolicy}
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
    cosepo.parse("default-src 'self' https://example.com")
  csp
  |> should.be_ok
  let valid_csp = result.unwrap(csp, ContentSecurityPolicy(directives: []))
  list.length(valid_csp.directives)
  |> should.equal(1)

  cosepo.parse("upgrade-insecure-requests;")
  |> should.be_ok
}

pub fn parse_error_test() {
  cosepo.parse("invalid-directive 'self'")
  |> result.unwrap_error("was not an error")
  |> should.equal("invalid-directive is not a valid directive name")

  cosepo.parse("default-src  ;")
  |> result.unwrap_error("was not an error")
  |> should.equal("missing directive values for default-src")

  cosepo.parse("upgrade-insecure-requests 'self';")
  |> result.unwrap_error("was not an error")
  |> should.equal("unexpected values for upgrade-insecure-requests directive")
}

pub fn serialize_test() {
  let assert Ok(directive1) =
    cosepo.new_directive("default-src", [
      "'self'", "https://example.com",
    ])
  let assert Ok(directive2) =
    cosepo.new_directive("img-src", ["'none'"])
  ContentSecurityPolicy([directive1, directive2])
  |> cosepo.serialize
  |> should.equal("default-src 'self' https://example.com; img-src 'none';")
}

pub fn serialize_upgrade_insecure_requests_test() {
  let assert Ok(directive1) =
    cosepo.new_directive("default-src", ["'none'"])
  let assert Ok(directive2) =
    cosepo.new_directive("upgrade-insecure-requests", [])

  ContentSecurityPolicy([directive1, directive2])
  |> cosepo.serialize
  |> should.equal("default-src 'none'; upgrade-insecure-requests;")
}

pub fn merge_to_empty_test() {
  let assert Ok(directive1) =
    cosepo.new_directive("default-src", ["'none'"])

  ContentSecurityPolicy([])
  |> cosepo.merge(directive1)
  |> should.equal(ContentSecurityPolicy([directive1]))
}

pub fn merge_to_new_directive_test() {
  let assert Ok(directive1) =
    cosepo.new_directive("default-src", ["'none'"])
  let assert Ok(directive2) =
    cosepo.new_directive("img-src", ["'none'"])
  ContentSecurityPolicy([directive1])
  |> cosepo.merge(directive2)
  |> should.equal(ContentSecurityPolicy([directive1, directive2]))
}

pub fn merge_to_existing_directive_test() {
  let assert Ok(directive1) =
    cosepo.new_directive("default-src", [
      "'self'", "http://example.com",
    ])
  let assert Ok(directive2) =
    cosepo.new_directive("default-src", ["https://example.com"])
  let assert Ok(merged_directive) =
    cosepo.new_directive("default-src", [
      "'self'", "http://example.com", "https://example.com",
    ])
  ContentSecurityPolicy([directive1])
  |> cosepo.merge(directive2)
  |> should.equal(ContentSecurityPolicy([merged_directive]))
}

pub fn set_test() {
  let assert Ok(directive1) =
    cosepo.new_directive("default-src", ["'self'"])
  let assert Ok(directive2) =
    cosepo.new_directive("default-src", ["'none'"])
  ContentSecurityPolicy([directive1])
  |> cosepo.set(directive2)
  |> should.equal(ContentSecurityPolicy([directive2]))
}

pub fn new_directive_test() {
  cosepo.new_directive("invalid-src", ["'self'"])
  |> should.be_error
}
