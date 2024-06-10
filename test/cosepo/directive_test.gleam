import cosepo/directive
import gleeunit
import gleeunit/should

pub fn main() {
  gleeunit.main()
}

pub fn new_directive_test() {
  directive.new_directive("invalid-src", ["'self'"])
  |> should.be_error

  directive.new_directive("default-src", ["'self'"])
  |> should.be_ok
}

pub fn get_name_test() {
  let assert Ok(d) = directive.new_directive("default-src", ["'self'"])
  d |> directive.get_name |> should.equal("default-src")
}

pub fn get_value_test() {
  let assert Ok(d) = directive.new_directive("default-src", ["'self'"])
  d |> directive.get_value |> should.equal(["'self'"])
}
