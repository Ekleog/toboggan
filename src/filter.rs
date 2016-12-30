use std::error::Error as StdError;
use std::str::FromStr;

use rustc_serialize::{Encodable, Encoder};
use serde::{de, Deserialize, Deserializer, Error};

use posix;

// Format for 4-arg filter: Arg[Op](a, b, jt, jf) ; effect: if a Op b then jt else jf
// TODO: Remove dead_code
#[allow(dead_code)]
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

impl Encodable for Filter {
    fn encode<S: Encoder>(&self, s: &mut S) -> Result<(), S::Error> {
        match *self {
            // Leafs
            Filter::Allow => s.emit_str("allow"),
            Filter::Kill  => s.emit_str("kill"),

            // Tools
            Filter::Log(ref f) => s.emit_struct("log", 2, |s| {
                s.emit_struct_field("do"  , 0, |s| s.emit_str("log syscall"))?;
                s.emit_struct_field("then", 1, |s| f.encode(s))?;
                Ok(())
            }),
            Filter::LogStr(ref msg, ref f) => s.emit_struct("log_str", 3, |s| {
                s.emit_struct_field("do"     , 0, |s| s.emit_str("log message"))?;
                s.emit_struct_field("message", 1, |s| s.emit_str(msg))?;
                s.emit_struct_field("then"   , 2, |s| f.encode(s))?;
                Ok(())
            }),

            // Arguments
            Filter::ArgEq(a, x, ref jt, ref jf) => s.emit_struct("arg_eq", 3, |s| {
                s.emit_struct_field("test" , 0, |s| format!("arg[{}] == {}", a, x).encode(s))?;
                s.emit_struct_field("true" , 1, |s| jt.encode(s))?;
                s.emit_struct_field("false", 2, |s| jf.encode(s))?;
                Ok(())
            }),

            Filter::ArgLeq(a, x, ref jt, ref jf) => s.emit_struct("arg_leq", 3, |s| {
                s.emit_struct_field("test" , 0, |s| format!("arg[{}] <= {}", a, x).encode(s))?;
                s.emit_struct_field("true" , 1, |s| jt.encode(s))?;
                s.emit_struct_field("false", 2, |s| jf.encode(s))?;
                Ok(())
            }),
            Filter::ArgLe(a, x, ref jt, ref jf) => s.emit_struct("arg_le", 3, |s| {
                s.emit_struct_field("test" , 0, |s| format!("arg[{}] < {}", a, x).encode(s))?;
                s.emit_struct_field("true" , 1, |s| jt.encode(s))?;
                s.emit_struct_field("false", 2, |s| jf.encode(s))?;
                Ok(())
            }),
            Filter::ArgGeq(a, x, ref jt, ref jf) => s.emit_struct("arg_geq", 3, |s| {
                s.emit_struct_field("test" , 0, |s| format!("arg[{}] >= {}", a, x).encode(s))?;
                s.emit_struct_field("true" , 1, |s| jt.encode(s))?;
                s.emit_struct_field("false", 2, |s| jf.encode(s))?;
                Ok(())
            }),
            Filter::ArgGe(a, x, ref jt, ref jf) => s.emit_struct("arg_ge", 3, |s| {
                s.emit_struct_field("test" , 0, |s| format!("arg[{}] > {}", a, x).encode(s))?;
                s.emit_struct_field("true" , 1, |s| jt.encode(s))?;
                s.emit_struct_field("false", 2, |s| jf.encode(s))?;
                Ok(())
            }),

            Filter::ArgHasBits(a, x, ref jt, ref jf) => s.emit_struct("arg_has_bits", 3, |s| {
                s.emit_struct_field("test" , 0, |s| format!("arg[{}] has bits {}", a, x).encode(s))?;
                s.emit_struct_field("true" , 1, |s| jt.encode(s))?;
                s.emit_struct_field("false", 2, |s| jf.encode(s))?;
                Ok(())
            }),
            Filter::ArgHasNoBits(a, x, ref jt, ref jf) => s.emit_struct("arg_has_no_bits", 3, |s| {
                s.emit_struct_field("test" , 0, |s| format!("arg[{}] has no bits {}", a, x).encode(s))?;
                s.emit_struct_field("true" , 1, |s| jt.encode(s))?;
                s.emit_struct_field("false", 2, |s| jf.encode(s))?;
                Ok(())
            }),
            Filter::ArgInBits(a, x, ref jt, ref jf) => s.emit_struct("arg_in_bits", 3, |s| {
                s.emit_struct_field("test" , 0, |s| format!("arg[{}] in bits {}", a, x).encode(s))?;
                s.emit_struct_field("true" , 1, |s| jt.encode(s))?;
                s.emit_struct_field("false", 2, |s| jf.encode(s))?;
                Ok(())
            }),

            // Paths
            Filter::PathIn(ref p, ref jt, ref jf) => s.emit_struct("path_in", 3, |s| {
                s.emit_struct_field("test" , 0, |s| format!("path in {}", p).encode(s))?;
                s.emit_struct_field("true" , 1, |s| jt.encode(s))?;
                s.emit_struct_field("false", 2, |s| jf.encode(s))?;
                Ok(())
            }),
            Filter::PathEq(ref p, ref jt, ref jf) => s.emit_struct("path_en", 3, |s| {
                s.emit_struct_field("test" , 0, |s| format!("path == {}", p).encode(s))?;
                s.emit_struct_field("true" , 1, |s| jt.encode(s))?;
                s.emit_struct_field("false", 2, |s| jf.encode(s))?;
                Ok(())
            }),
        }
    }
}

struct FilterVisitor;

fn parse<T: FromStr, E: Error>(s: &str) -> Result<T, E> where T::Err: StdError {
    match s.parse() {
        Ok(r)  => Ok(r),
        Err(e) => Err(E::custom(e.description())),
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
                    test = Some(v.visit_value::<String>()?);
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
            let jt = jt.unwrap();
            let jf = jf.unwrap();
            if test.starts_with("path") {
                if test.starts_with("path in ") {
                    return Ok(Filter::PathIn(String::from(&test[8..]), Box::new(jt), Box::new(jf)));
                } else if test.starts_with("path == ") {
                    return Ok(Filter::PathEq(String::from(&test[8..]), Box::new(jt), Box::new(jf)));
                } else {
                    return Err(M::Error::invalid_value(&format!("Invalid path test: '{}'", test)));
                }
            } else if test.starts_with("arg[") {
                let arg = parse(&test[5..6])?;
                if &test[6..11] == "] == " {
                    return Ok(Filter::ArgEq(arg, parse(&test[11..])?, Box::new(jt), Box::new(jf)));
                } else if &test[6..11] == "] <= " {
                    return Ok(Filter::ArgLeq(arg, parse(&test[11..])?, Box::new(jt), Box::new(jf)));
                } else if &test[6..10] == "] < " {
                    return Ok(Filter::ArgLe(arg, parse(&test[10..])?, Box::new(jt), Box::new(jf)));
                } else if &test[6..11] == "] >= " {
                    return Ok(Filter::ArgGeq(arg, parse(&test[11..])?, Box::new(jt), Box::new(jf)));
                } else if &test[6..10] == "] > " {
                    return Ok(Filter::ArgGe(arg, parse(&test[10..])?, Box::new(jt), Box::new(jf)));
                } else if &test[6..17] == "] has bits " {
                    return Ok(Filter::ArgHasBits(arg, parse(&test[17..])?, Box::new(jt), Box::new(jf)));
                } else if &test[6..20] == "] has no bits " {
                    return Ok(Filter::ArgHasBits(arg, parse(&test[20..])?, Box::new(jt), Box::new(jf)));
                } else if &test[6..16] == "] in bits " {
                    return Ok(Filter::ArgHasBits(arg, parse(&test[16..])?, Box::new(jt), Box::new(jf)));
                } else {
                    return Err(M::Error::invalid_value(&format!("Invalid arg test: '{}'", test)));
                }
            } else {
                return Err(M::Error::invalid_value(&format!("Invalid test: '{}'", test)));
            }
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
