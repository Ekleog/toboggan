#!/bin/sh

# Copyright (C) 2016  Leo Gaspard
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

if [ \! $# -eq 1 ]; then
    echo "Usage: $0 [path to your {linux-headers}/asm-x86_64/unistd_64.h]"
    exit 1
fi

syscalls="$(cat $1 | grep __NR_ | sed -e 's/^.*__NR_//')"

exec > src/syscalls.rs

echo "/*"
echo " * Copyright (C) 2016  Leo Gaspard"
echo " *"
echo " * This program is free software: you can redistribute it and/or modify"
echo " * it under the terms of the GNU General Public License as published by"
echo " * the Free Software Foundation, either version 3 of the License, or"
echo " * (at your option) any later version."
echo " *"
echo " * This program is distributed in the hope that it will be useful,"
echo " * but WITHOUT ANY WARRANTY; without even the implied warranty of"
echo " * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the"
echo " * GNU General Public License for more details."
echo " *"
echo " * You should have received a copy of the GNU General Public License"
echo " * along with this program.  If not, see <http://www.gnu.org/licenses/>."
echo " */"
echo ""
echo "use serde::{de, Deserialize, Deserializer, Serialize, Serializer};"
echo ""
echo "#[allow(non_camel_case_types)]"
echo "#[derive(PartialEq, Eq, Clone, Copy, Debug, Hash)]"
echo "pub enum Syscall {"
echo "$syscalls" | awk '{ print "    " $1 " = " $2 "," }'
echo "}"
echo ""
echo "pub fn from(x: u64) -> Option<Syscall> {"
echo "    match x {"
echo "$syscalls" | awk '{ print "        " $2 " => Some(Syscall::" $1 ")," }'
echo "        _ => None,"
echo "    }"
echo "}"
echo ""
echo "pub fn from_str(x: &str) -> Option<Syscall> {"
echo "    match x {"
echo "$syscalls" | awk '{ print "        \"" $1 "\" => Some(Syscall::" $1 ")," }'
echo "        _ => None,"
echo "    }"
echo "}"
echo ""
echo "impl Serialize for Syscall {"
echo "    fn serialize<S: Serializer>(&self, s: &mut S) -> Result<(), S::Error> {"
echo "        s.serialize_str(match *self {"
echo "$syscalls" | awk '{ print "            Syscall::" $1 " => \"" $1 "\"," }'
echo "        })"
echo "    }"
echo "}"
echo ""
echo "struct SyscallVisitor;"
echo ""
echo "impl de::Visitor for SyscallVisitor {"
echo "    type Value = Syscall;"
echo ""
echo "    fn visit_str<E: de::Error>(&mut self, v: &str) -> Result<Syscall, E> {"
echo "        if let Some(res) = from_str(v) {"
echo "            Ok(res)"
echo "        } else {"
echo "            Err(E::invalid_value(&format!(\"Unknown Syscall variant: {}\", v)))"
echo "        }"
echo "    }"
echo "}"
echo ""
echo "impl Deserialize for Syscall {"
echo "    fn deserialize<D: Deserializer>(d: &mut D) -> Result<Syscall, D::Error> {"
echo "        d.deserialize_str(SyscallVisitor)"
echo "    }"
echo "}"
