/*
 * Copyright (C) 2016  Leo Gaspard
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
