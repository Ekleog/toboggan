#!/bin/sh

if [ \! $# -eq 1 ]; then
    echo "Usage: $0 [path to your {linux-headers}/asm-x86_64/unistd_64.h]"
    exit 1
fi

syscalls="$(cat $1 | grep __NR_ | sed -e 's/^.*__NR_//')"

exec > src/syscalls.rs

echo "use serde::{de, Deserialize, Deserializer};"
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
echo "struct SyscallVisitor;"
echo ""
echo "impl de::Visitor for SyscallVisitor {"
echo "    type Value = Syscall;"
echo ""
echo "    fn visit_str<E: de::Error>(&mut self, v: &str) -> Result<Syscall, E> {"
echo "        match v {"
echo "$syscalls" | awk '{ print "            \"" $1 "\" => Ok(Syscall::" $1 ")," }'
echo "            _ => Err(E::invalid_value(&format!(\"Unknown Syscall variant: {}\", v))),"
echo "        }"
echo "    }"
echo "}"
echo ""
echo "impl Deserialize for Syscall {"
echo "    fn deserialize<D: Deserializer>(d: &mut D) -> Result<Syscall, D::Error> {"
echo "        d.deserialize_str(SyscallVisitor)"
echo "    }"
echo "}"
