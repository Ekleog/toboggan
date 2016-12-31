// Warning! I didn't find how to parameterize the M, so make sure the MapVisitor type is called M!
macro_rules! get_if_unset {
    ( $visitor:expr, $var:ident, $name:expr ; $typ:ty ) => {{
        if $var.is_some() {
            return Err(M::Error::duplicate_field($name))
        }
        $var = Some($visitor.visit_value::<$typ>()?);
    }};
}

macro_rules! println_stderr {
    ( $( $x:expr ),* ) => {{
        writeln!(::std::io::stderr(), $( $x ),*)
            .expect("failed printing to stderr")
    }};
}
