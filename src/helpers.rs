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

// Wasn't able to find a cleaner way to have this
macro_rules! count {
    ( )                         => { 0 };
    ( $x:expr $( , $y:expr )* ) => { 1 + count![ $( $y ),* ] };
}
macro_rules! serialize_map {
    ( $s:expr, { $( $k:expr => $v:expr ),* } ) => {{
        let mut state = $s.serialize_map(Some(count!($($k),*)))?;
        $(
            $s.serialize_map_key(&mut state, $k)?;
            $s.serialize_map_value(&mut state, $v)?;
        )*
        $s.serialize_map_end(state)
    }};
}
