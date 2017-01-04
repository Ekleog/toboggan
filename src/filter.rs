/*
 * Copyright (C) 2016-2017  Leo Gaspard
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

use std::error::Error as StdError;
use std::str::FromStr;

use regex::Regex;
#[allow(unused_imports)] // Rustc seems to wrongly detect Error as unused. TODO: remove when fixed?
use serde::{de, Deserialize, Deserializer, Error, Serialize, Serializer};

use posix;

// Format for 4-arg filter: Arg[Op](a, b, jt, jf) ; effect: if a Op b then jt else jf
#[derive(PartialEq, Eq, Debug, Clone)]
pub enum Filter {
    // Leafs
    Allow,
    Kill,
    Ask,

    // Tools
    Eval(String),
    Log(Box<Filter>),
    LogStr(String, Box<Filter>),

    // Arguments
    ArgEq(usize, u64, Box<Filter>, Box<Filter>),

    ArgLeq(usize, u64, Box<Filter>, Box<Filter>),
    ArgLe(usize, u64, Box<Filter>, Box<Filter>),
    ArgGeq(usize, u64, Box<Filter>, Box<Filter>),
    ArgGe(usize, u64, Box<Filter>, Box<Filter>),

    ArgHasBits(usize, u64, Box<Filter>, Box<Filter>),   // a & b == b
    ArgHasNoBits(usize, u64, Box<Filter>, Box<Filter>), // a & b == 0
    ArgInBits(usize, u64, Box<Filter>, Box<Filter>),    // a & b == a

    // Path
    PathIn(String, Box<Filter>, Box<Filter>),
    PathEq(String, Box<Filter>, Box<Filter>),

    RealPathIn(String, Box<Filter>, Box<Filter>),
    RealPathEq(String, Box<Filter>, Box<Filter>),
}

#[derive(Debug, PartialEq, Eq)]
pub enum FilterResult {
    Allow,
    Kill,
    Ask,
}

impl From<posix::Action> for FilterResult {
    fn from(a: posix::Action) -> FilterResult {
        match a {
            posix::Action::Allow => FilterResult::Allow,
            posix::Action::Kill  => FilterResult::Kill,
        }
    }
}

pub fn eval(f: &Filter, sys: &posix::SyscallInfo) -> FilterResult {
    match *f {
        // Leafs
        Filter::Allow => FilterResult::Allow,
        Filter::Kill  => FilterResult::Kill,
        Filter::Ask   => FilterResult::Ask,

        // Tools
        Filter::Eval(ref s) => FilterResult::from(posix::call_script(s, sys)),
        Filter::Log(ref ff) => {
            println!(
                "toboggan: {:?} [path = '{}', realpath = '{}'] ({}, {}, {}, {}, {}, {})",
                sys.syscall, sys.path, sys.realpath,
                sys.args[0], sys.args[1], sys.args[2], sys.args[3], sys.args[4], sys.args[5]
            );
            eval(&*ff, sys)
        }
        Filter::LogStr(ref s, ref ff) => {
            println!("toboggan: {}", s);
            eval(&*ff, sys)
        }

        // Arguments
        Filter::ArgEq(a, x, ref jt, ref jf) => {
            if sys.args[a] == x { eval(&*jt, sys) }
            else                { eval(&*jf, sys) }
        }

        Filter::ArgLeq(a, x, ref jt, ref jf) => {
            if sys.args[a] <= x { eval(&*jt, sys) }
            else                { eval(&*jf, sys) }
        }
        Filter::ArgLe(a, x, ref jt, ref jf) => {
            if sys.args[a] < x { eval(&*jt, sys) }
            else               { eval(&*jf, sys) }
        }
        Filter::ArgGeq(a, x, ref jt, ref jf) => {
            if sys.args[a] >= x { eval(&*jt, sys) }
            else                { eval(&*jf, sys) }
        }
        Filter::ArgGe(a, x, ref jt, ref jf) => {
            if sys.args[a] > x { eval(&*jt, sys) }
            else               { eval(&*jf, sys) }
        }

        Filter::ArgHasBits(a, x, ref jt, ref jf) => {
            if sys.args[a] & x == x { eval(&*jt, sys) }
            else                    { eval(&*jf, sys) }
        }
        Filter::ArgHasNoBits(a, x, ref jt, ref jf) => {
            if sys.args[a] & x == 0 { eval(&*jt, sys) }
            else                    { eval(&*jf, sys) }
        }
        Filter::ArgInBits(a, x, ref jt, ref jf) => {
            if sys.args[a] & x == sys.args[a] { eval(&*jt, sys) }
            else                              { eval(&*jf, sys) }
        }

        // Path
        // TODO: check /foobar is not considered in /foo
        Filter::PathIn(ref s, ref jt, ref jf) => {
            if sys.path.starts_with(s) { eval(&*jt, sys) }
            else                       { eval(&*jf, sys) }
        }
        Filter::PathEq(ref s, ref jt, ref jf) => {
            if sys.path == *s { eval(&*jt, sys) }
            else              { eval(&*jf, sys) }
        }

        Filter::RealPathIn(ref s, ref jt, ref jf) => {
            if sys.realpath.starts_with(s) { eval(&*jt, sys) }
            else                           { eval(&*jf, sys) }
        }
        Filter::RealPathEq(ref s, ref jt, ref jf) => {
            if sys.realpath == *s { eval(&*jt, sys) }
            else                  { eval(&*jf, sys) }
        }
    }
}

fn serialize_test<S: Serializer>(s: &mut S, test: &str, jt: &Box<Filter>, jf: &Box<Filter>)
        -> Result<(), S::Error> {
    serialize_map!(s, {
        "test"  => test,
        "true"  => jt,
        "false" => jf
    })
}

impl Serialize for Filter {
    fn serialize<S: Serializer>(&self, s: &mut S) -> Result<(), S::Error> {
        use self::Filter::*;

        match *self {
            // Leafs
            Allow       => s.serialize_str("allow"),
            Kill        => s.serialize_str("kill"),
            Ask         => s.serialize_str("ask"),

            // Tools
            Eval(ref e) => serialize_map!(s, {
                "do"     => "eval",
                "script" => e
            }),
            Log(ref then) => serialize_map!(s, {
                "do"   => "log syscall",
                "then" => then
            }),
            LogStr(ref msg, ref then) => serialize_map!(s, {
                "do"      => "log message",
                "message" => msg,
                "then"    => then
            }),

            // Arguments
            ArgEq(a, x, ref jt, ref jf)  => serialize_test(s, &format!("arg[{}] == {}", a, x), jt, jf),

            ArgLeq(a, x, ref jt, ref jf) => serialize_test(s, &format!("arg[{}] <= {}", a, x), jt, jf),
            ArgLe(a, x, ref jt, ref jf)  => serialize_test(s, &format!("arg[{}] < {}", a, x), jt, jf),
            ArgGeq(a, x, ref jt, ref jf) => serialize_test(s, &format!("arg[{}] >= {}", a, x), jt, jf),
            ArgGe(a, x, ref jt, ref jf)  => serialize_test(s, &format!("arg[{}] > {}", a, x), jt, jf),

            ArgHasBits(a, x, ref jt, ref jf)   => serialize_test(s, &format!("arg[{}] has bits {}", a, x), jt, jf),
            ArgHasNoBits(a, x, ref jt, ref jf) => serialize_test(s, &format!("arg[{}] has no bits {}", a, x), jt, jf),
            ArgInBits(a, x, ref jt, ref jf)    => serialize_test(s, &format!("arg[{}] in bits {}", a, x), jt, jf),

            // Path
            PathIn(ref p, ref jt, ref jf) => serialize_test(s, &format!("path in {}", p), jt, jf),
            PathEq(ref p, ref jt, ref jf) => serialize_test(s, &format!("path == {}", p), jt, jf),

            RealPathIn(ref p, ref jt, ref jf) => serialize_test(s, &format!("realpath in {}", p), jt, jf),
            RealPathEq(ref p, ref jt, ref jf) => serialize_test(s, &format!("realpath == {}", p), jt, jf),
        }
    }
}

struct FilterVisitor;

fn parse_int<T: FromStr, E: Error>(s: &str) -> Result<T, E> where T::Err: StdError {
    match s.parse() {
        Ok(r)  => Ok(r),
        Err(e) => Err(E::custom(e.description())),
    }
}

enum FilterTest {
    ArgEq(usize, u64),

    ArgLeq(usize, u64),
    ArgLe(usize, u64),
    ArgGeq(usize, u64),
    ArgGe(usize, u64),

    ArgHasBits(usize, u64),
    ArgHasNoBits(usize, u64),
    ArgInBits(usize, u64),

    PathIn(String),
    PathEq(String),

    RealPathIn(String),
    RealPathEq(String),
}

fn parse_test<E: Error>(test: String) -> Result<FilterTest, E> {
    let test = test.to_lowercase();
    lazy_static! {
        static ref ARG_RE: Regex = Regex::new(r"(?x)
            ^arg\s*\[\s*(?P<arg>[0-5])\s*\]\s+                            # arg[a]
            (?-x)(?P<op>==|<=|<|>=|>|has bits|has no bits|in bits)\s+(?x) # operator
            (?P<val>[1-9][0-9]*)$                                         # value, integer
        ").unwrap();
        static ref PATH_RE: Regex = Regex::new(r"(?x)
            ^(?P<var>path|realpath)\s+ # 'path'
            (?P<op>in|==)\s+           # operator
            (?P<path>.*)$              # path
        ").unwrap();
    }
    if let Some(c) = ARG_RE.captures(&test) {
        let arg = parse_int(c.name("arg").unwrap())?;
        let val = parse_int(c.name("val").unwrap())?;
        match c.name("op").unwrap() {
            "==" => Ok(FilterTest::ArgEq(arg, val)),

            "<=" => Ok(FilterTest::ArgLeq(arg, val)),
            "<"  => Ok(FilterTest::ArgLe(arg, val)),
            ">=" => Ok(FilterTest::ArgGeq(arg, val)),
            ">"  => Ok(FilterTest::ArgGe(arg, val)),

            "has bits"    => Ok(FilterTest::ArgHasBits(arg, val)),
            "has no bits" => Ok(FilterTest::ArgHasNoBits(arg, val)),
            "in bits"     => Ok(FilterTest::ArgInBits(arg, val)),

            op => Err(E::invalid_value(&format!("Unknown arg operator: {}", op))),
        }
    } else if let Some(c) = PATH_RE.captures(&test) {
        let path = c.name("path").unwrap();
        match c.name("var").unwrap() {
            "path" =>
                match c.name("op").unwrap() {
                    "in" => Ok(FilterTest::PathIn(String::from(path))),
                    "==" => Ok(FilterTest::PathEq(String::from(path))),
                    op   => Err(E::invalid_value(&format!("Unknown path operator: {}", op))),
                },
            "realpath" =>
                match c.name("op").unwrap() {
                    "in" => Ok(FilterTest::RealPathIn(String::from(path))),
                    "==" => Ok(FilterTest::RealPathEq(String::from(path))),
                    op   => Err(E::invalid_value(&format!("Unknown path operator: {}", op))),
                },
            var => Err(E::invalid_value(&format!("Unknown path variable: {}", var))),
        }
    } else {
        Err(E::invalid_value(&format!("Invalid test: '{}'", test)))
    }
}

impl de::Visitor for FilterVisitor {
    type Value = Filter;

    fn visit_str<E: de::Error>(&mut self, v: &str) -> Result<Filter, E> {
        match v {
            "allow" => Ok(Filter::Allow),
            "kill"  => Ok(Filter::Kill),
            "ask"   => Ok(Filter::Ask),
            _       => Err(E::invalid_value(&format!("Unable to parse string '{}' as Filter", v))),
        }
    }

    fn visit_map<M: de::MapVisitor>(&mut self, mut v: M) -> Result<Filter, M::Error> {
        let mut do_     = None;
        let mut message = None;
        let mut then    = None;
        let mut script  = None;
        let mut test    = None;
        let mut jt      = None;
        let mut jf      = None;

        while let Some(k) = v.visit_key::<String>()? {
            match k.as_ref() {
                "do"      => get_if_unset!(v, do_, "do"          ; String),
                "message" => get_if_unset!(v, message, "message" ; String),
                "then"    => get_if_unset!(v, then, "then"       ; Filter),
                "script"  => get_if_unset!(v, script, "script"   ; String),
                "test"    => {
                    let mut t = None;
                    get_if_unset!(v, t, "test" ; String);
                    test = Some(parse_test(t.unwrap())?);
                }
                "true"    => get_if_unset!(v, jt, "true"         ; Filter),
                "false"   => get_if_unset!(v, jf, "false"        ; Filter),
                _         => return Err(M::Error::unknown_field(&k)),
            }
        }
        v.end()?;

        // TODO: clean this up, it's becoming a mess
        if do_.is_some() {
            // Log or LogStr
            if test.is_some() || jt.is_some() || jf.is_some() {
                return Err(M::Error::custom("Cannot have both 'do' and test-like keys"));
            }
            if script.is_some() {
                if then.is_some() {
                    return Err(M::Error::custom("Cannot have both 'script' and 'then' keys"));
                }
                if do_.unwrap() != "eval" {
                    return Err(M::Error::custom("Cannot have 'script' with a non-'eval' do"));
                }
                return Ok(Filter::Eval(script.unwrap()));
            }
            if !then.is_some() {
                return Err(M::Error::custom("Cannot have a 'do' without a 'then'"));
            }
            let then = then.unwrap();
            match do_.unwrap().as_ref() {
                "log syscall" => {
                    if message.is_some() {
                        return Err(M::Error::custom("Cannot have a 'message' field in a 'log syscall'"));
                    }
                    return Ok(Filter::Log(Box::new(then)));
                },
                "log message" => {
                    if !message.is_some() {
                        return Err(M::Error::missing_field("message"));
                    }
                    return Ok(Filter::LogStr(message.unwrap(), Box::new(then)));
                },
                do_ => return Err(M::Error::invalid_value(&format!("Unknown value for 'do': {}", do_))),
            }
        } else if test.is_some() {
            if !jt.is_some() {
                return Err(M::Error::missing_field("true"));
            }
            if !jf.is_some() {
                return Err(M::Error::missing_field("false"));
            }
            if then.is_some() || message.is_some() {
                return Err(M::Error::custom("Cannot have both 'test' and action-like keys"));
            }
            let test = test.unwrap();
            let jt = Box::new(jt.unwrap());
            let jf = Box::new(jf.unwrap());
            Ok(match test {
                FilterTest::ArgEq(a, x) => Filter::ArgEq(a, x, jt, jf),

                FilterTest::ArgLeq(a, x) => Filter::ArgLeq(a, x, jt, jf),
                FilterTest::ArgLe(a, x)  => Filter::ArgLe(a, x, jt, jf),
                FilterTest::ArgGeq(a, x) => Filter::ArgGeq(a, x, jt, jf),
                FilterTest::ArgGe(a, x)  => Filter::ArgGe(a, x, jt, jf),

                FilterTest::ArgHasBits(a, x)   => Filter::ArgHasBits(a, x, jt, jf),
                FilterTest::ArgHasNoBits(a, x) => Filter::ArgHasNoBits(a, x, jt, jf),
                FilterTest::ArgInBits(a, x)    => Filter::ArgInBits(a, x, jt, jf),

                FilterTest::PathIn(s) => Filter::PathIn(s, jt, jf),
                FilterTest::PathEq(s) => Filter::PathEq(s, jt, jf),

                FilterTest::RealPathIn(s) => Filter::RealPathIn(s, jt, jf),
                FilterTest::RealPathEq(s) => Filter::RealPathEq(s, jt, jf),
            })
        } else {
            return Err(M::Error::missing_field("Filter is missing both 'do' and 'test'"));
        }
    }
}

impl Deserialize for Filter {
    fn deserialize<D: Deserializer>(d: &mut D) -> Result<Filter, D::Error> {
        d.deserialize(FilterVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use posix;
    use syscalls::Syscall;
    use serde_json;

    #[test]
    fn action_to_filter_result() {
        assert_eq!(FilterResult::from(posix::Action::Allow), FilterResult::Allow);
        assert_eq!(FilterResult::from(posix::Action::Kill) , FilterResult::Kill);
    }

    fn complex_filter() -> Filter {
        Filter::Log(
            Box::new(Filter::PathIn(
                String::from("/usr/share"),
                Box::new(Filter::LogStr(
                    String::from("In aliquam aliquet tortor ac viverra."),
                    Box::new(Filter::ArgGeq(
                        3, 42,
                        Box::new(Filter::Ask),
                        Box::new(Filter::ArgHasNoBits(
                            2, 1337,
                            Box::new(Filter::ArgInBits(
                                2, 1337,
                                Box::new(Filter::LogStr(
                                    String::from("arg[2] == 0"),
                                    Box::new(Filter::Ask)
                                )),
                                Box::new(Filter::Kill)
                            )),
                            Box::new(Filter::Allow)
                        ))
                    ))
                )),
                Box::new(Filter::ArgHasBits(
                    2, 1337,
                    Box::new(Filter::ArgLe(
                        3, 42,
                        Box::new(Filter::Eval(String::from("/boot/whatisthisdoinghere.pl"))),
                        Box::new(Filter::ArgGe(
                            3, 42,
                            Box::new(Filter::Kill),
                            Box::new(Filter::Allow)
                        ))
                    )),
                    Box::new(Filter::Allow)
                ))
            ))
        )
    }

    fn other_filter() -> Filter {
        Filter::ArgEq(0, 1,
            Box::new(Filter::ArgLeq(2, 3, Box::new(Filter::Allow), Box::new(Filter::Kill))),
            Box::new(Filter::PathEq(
                String::from("/var/run"),
                Box::new(Filter::Allow),
                Box::new(Filter::Kill)
            ))
        )
    }

    fn example_syscall() -> posix::SyscallInfo {
        posix::SyscallInfo {
            syscall: Syscall::open,
            args: [5, 4, 3, 2, 1, 0],
            path: String::from("/home/mallory/hahaha"),
            realpath: String::from("/usr/share"),
        }
    }

    #[test]
    fn evaluate_filters() {
        let sys = example_syscall();

        assert_eq!(eval(&Filter::Allow, &sys), FilterResult::Allow);
        assert_eq!(eval(&Filter::Kill, &sys), FilterResult::Kill);
        assert_eq!(eval(&Filter::Ask, &sys), FilterResult::Ask);

        assert_eq!(eval(&Filter::Eval(String::from("tests/allow.sh")), &sys), FilterResult::Allow);
        assert_eq!(eval(&Filter::Eval(String::from("tests/kill.sh")), &sys), FilterResult::Kill);
        assert_eq!(eval(&Filter::Log(Box::new(Filter::Allow)), &sys), FilterResult::Allow);
        assert_eq!(eval(&Filter::LogStr(String::new(), Box::new(Filter::Ask)), &sys), FilterResult::Ask);

        assert_eq!(eval(&Filter::ArgEq(0, 5, Box::new(Filter::Ask), Box::new(Filter::Kill)), &sys),
                   FilterResult::Ask);
        assert_eq!(eval(&Filter::ArgEq(0, 4, Box::new(Filter::Ask), Box::new(Filter::Kill)), &sys),
                   FilterResult::Kill);

        assert_eq!(eval(&Filter::ArgLeq(1, 6, Box::new(Filter::Ask), Box::new(Filter::Kill)), &sys),
                   FilterResult::Ask);
        assert_eq!(eval(&Filter::ArgLeq(1, 3, Box::new(Filter::Ask), Box::new(Filter::Kill)), &sys),
                   FilterResult::Kill);
        assert_eq!(eval(&Filter::ArgLe(2, 3, Box::new(Filter::Ask), Box::new(Filter::Kill)), &sys),
                   FilterResult::Kill);
        assert_eq!(eval(&Filter::ArgLe(2, 5, Box::new(Filter::Ask), Box::new(Filter::Kill)), &sys),
                   FilterResult::Ask);
        assert_eq!(eval(&Filter::ArgGeq(3, 2, Box::new(Filter::Ask), Box::new(Filter::Kill)), &sys),
                   FilterResult::Ask);
        assert_eq!(eval(&Filter::ArgGeq(3, 3, Box::new(Filter::Ask), Box::new(Filter::Kill)), &sys),
                   FilterResult::Kill);
        assert_eq!(eval(&Filter::ArgGe(4, 0, Box::new(Filter::Ask), Box::new(Filter::Kill)), &sys),
                   FilterResult::Ask);
        assert_eq!(eval(&Filter::ArgGe(4, 3, Box::new(Filter::Ask), Box::new(Filter::Kill)), &sys),
                   FilterResult::Kill);

        assert_eq!(eval(&Filter::ArgHasBits(0, 1, Box::new(Filter::Ask), Box::new(Filter::Kill)), &sys),
                   FilterResult::Ask);
        assert_eq!(eval(&Filter::ArgHasBits(0, 3, Box::new(Filter::Ask), Box::new(Filter::Kill)), &sys),
                   FilterResult::Kill);
        assert_eq!(eval(&Filter::ArgHasNoBits(0, 2, Box::new(Filter::Ask), Box::new(Filter::Kill)), &sys),
                   FilterResult::Ask);
        assert_eq!(eval(&Filter::ArgHasNoBits(0, 3, Box::new(Filter::Ask), Box::new(Filter::Kill)), &sys),
                   FilterResult::Kill);
        assert_eq!(eval(&Filter::ArgInBits(0, 13, Box::new(Filter::Ask), Box::new(Filter::Kill)), &sys),
                   FilterResult::Ask);
        assert_eq!(eval(&Filter::ArgInBits(0, 4, Box::new(Filter::Ask), Box::new(Filter::Kill)), &sys),
                   FilterResult::Kill);

        assert_eq!(eval(&Filter::PathIn(String::from("/home/mallory"),
                            Box::new(Filter::Ask), Box::new(Filter::Kill)), &sys),
                   FilterResult::Ask);
        assert_eq!(eval(&Filter::PathIn(String::from("/home/mallory/hahaha/haha"),
                            Box::new(Filter::Ask), Box::new(Filter::Kill)), &sys),
                   FilterResult::Kill);
        assert_eq!(eval(&Filter::PathEq(String::from("/home/mallory"),
                            Box::new(Filter::Ask), Box::new(Filter::Kill)), &sys),
                   FilterResult::Kill);
        assert_eq!(eval(&Filter::PathEq(String::from("/home/mallory/hahaha"),
                            Box::new(Filter::Ask), Box::new(Filter::Kill)), &sys),
                   FilterResult::Ask);

        assert_eq!(eval(&complex_filter(), &sys), FilterResult::Allow);
    }

    #[test]
    fn serialize_filter() {
        assert_eq!(serde_json::to_string_pretty(&complex_filter()).unwrap(),
            r#"{
  "do": "log syscall",
  "then": {
    "test": "path in /usr/share",
    "true": {
      "do": "log message",
      "message": "In aliquam aliquet tortor ac viverra.",
      "then": {
        "test": "arg[3] >= 42",
        "true": "ask",
        "false": {
          "test": "arg[2] has no bits 1337",
          "true": {
            "test": "arg[2] in bits 1337",
            "true": {
              "do": "log message",
              "message": "arg[2] == 0",
              "then": "ask"
            },
            "false": "kill"
          },
          "false": "allow"
        }
      }
    },
    "false": {
      "test": "arg[2] has bits 1337",
      "true": {
        "test": "arg[3] < 42",
        "true": {
          "do": "eval",
          "script": "/boot/whatisthisdoinghere.pl"
        },
        "false": {
          "test": "arg[3] > 42",
          "true": "kill",
          "false": "allow"
        }
      },
      "false": "allow"
    }
  }
}"#);

        assert_eq!(serde_json::to_string_pretty(&other_filter()).unwrap(), r#"{
  "test": "arg[0] == 1",
  "true": {
    "test": "arg[2] <= 3",
    "true": "allow",
    "false": "kill"
  },
  "false": {
    "test": "path == /var/run",
    "true": "allow",
    "false": "kill"
  }
}"#);
    }

    #[test]
    fn deserialize_filter() {
        assert_eq!(
            serde_json::from_str::<Filter>(&serde_json::to_string(&complex_filter()).unwrap()).unwrap(),
            complex_filter()
        );
        assert_eq!(
            serde_json::from_str::<Filter>(&serde_json::to_string(&other_filter()).unwrap()).unwrap(),
            other_filter()
        );
    }
}
