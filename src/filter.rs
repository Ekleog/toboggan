use rustc_serialize::{Encodable, Encoder};

use posix;

// Format for 4-arg filter: Arg[Op](a, b, jt, jf) ; effect: if a Op b then jt else jf
// TODO: Remove dead_code
#[allow(dead_code)]
#[derive(PartialEq, Eq)]
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
