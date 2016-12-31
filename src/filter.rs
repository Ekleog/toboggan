use std::error::Error as StdError;
use std::str::FromStr;

use regex::Regex;
use serde::{de, Deserialize, Deserializer, Error};

use posix;

// Format for 4-arg filter: Arg[Op](a, b, jt, jf) ; effect: if a Op b then jt else jf
#[derive(PartialEq, Eq, Debug)]
pub enum Filter {
    // Leafs
    Allow,
    Kill,

    // Tools
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
}

pub fn eval(f: &Filter, sys: &posix::SyscallInfo) -> posix::Action {
    match *f {
        // Leafs
        Filter::Allow => posix::Action::Allow,
        Filter::Kill  => posix::Action::Kill,

        // Tools
        Filter::Log(ref ff) => {
            println!(
                "toboggan: {:?} [path = '{}'] ({}, {}, {}, {}, {}, {})",
                sys.syscall, sys.path,
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
        Filter::PathIn(ref s, ref jt, ref jf) => {
            if sys.path.starts_with(s) { eval(&*jt, sys) }
            else                       { eval(&*jf, sys) }
        }
        Filter::PathEq(ref s, ref jt, ref jf) => {
            if sys.path == *s { eval(&*jt, sys) }
            else              { eval(&*jf, sys) }
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
}

fn parse_test<E: Error>(test: String) -> Result<FilterTest, E> {
    let test = test.to_lowercase();
    lazy_static! {
        /* TODO: uncomment after checking x flag
        static ref ARG_RE: Regex = Regex::new(r"(?x)
            ^arg\s*\[\s*(?P<arg>[0-5])\s*\]\s+                   # arg[a]
            (?P<op>==|<=|<|>=|>|has bits|has no bits|in bits)\s+ # operator
            (?P<val>[1-9][0-9]*)$                                # value, integer
        ").unwrap();
        static ref PATH_RE: Regex = Regex::new(r"(?x)
            ^path\s+         # 'path'
            (?P<op>in|==)\s+ # operator
            (?P<path>.*)$    # path
        ").unwrap();
        */
        static ref ARG_RE: Regex = Regex::new(r"^arg\s*\[\s*(?P<arg>[0-5])\s*\]\s+(?P<op>==|<=|<|>=|>|has bits|has no bits|in bits)\s+(?P<val>[1-9][0-9]*)$").unwrap();
        static ref PATH_RE: Regex = Regex::new(r"^path\s+(?P<op>in|==)\s+(?P<path>.*)$").unwrap();
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
        match c.name("op").unwrap() {
            "in" => Ok(FilterTest::PathIn(String::from(path))),
            "==" => Ok(FilterTest::PathEq(String::from(path))),
            op   => Err(E::invalid_value(&format!("Unknown path operator: {}", op))),
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
            _       => Err(E::invalid_value(&format!("Unable to parse string '{}' as Filter", v))),
        }
    }

    fn visit_map<M: de::MapVisitor>(&mut self, mut v: M) -> Result<Filter, M::Error> {
        let mut do_     = None;
        let mut message = None;
        let mut then    = None;
        let mut test    = None;
        let mut jt      = None;
        let mut jf      = None;

        while let Some(k) = v.visit_key::<String>()? {
            match k.as_ref() {
                "do" => {
                    if do_.is_some() {
                        return Err(M::Error::duplicate_field("do"));
                    }
                    do_ = Some(v.visit_value::<String>()?);
                },
                "message" => {
                    if message.is_some() {
                        return Err(M::Error::duplicate_field("message"));
                    }
                    message = Some(v.visit_value()?);
                },
                "then" => {
                    if then.is_some() {
                        return Err(M::Error::duplicate_field("then"));
                    }
                    then = Some(v.visit_value()?);
                },
                "test" => {
                    if test.is_some() {
                        return Err(M::Error::duplicate_field("test"));
                    }
                    test = Some(parse_test(v.visit_value::<String>()?)?);
                },
                "true" => {
                    if jt.is_some() {
                        return Err(M::Error::duplicate_field("jt"));
                    }
                    jt = Some(v.visit_value()?);
                },
                "false" => {
                    if jf.is_some() {
                        return Err(M::Error::duplicate_field("jf"));
                    }
                    jf = Some(v.visit_value()?);
                },
                _ => return Err(M::Error::unknown_field(&k)),
            }
        }
        v.end()?;

        if do_.is_some() {
            // Log or LogStr
            if test.is_some() || jt.is_some() || jf.is_some() {
                return Err(M::Error::custom("Cannot have both 'do' and test-like keys"));
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
