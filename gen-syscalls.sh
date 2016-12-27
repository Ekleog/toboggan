#!/bin/sh

if [ \! $# -eq 1 ]; then
    echo "Usage: $0 [path to your {linux-headers}/asm-x86_64/unistd_64.h]"
    exit 1
fi

syscalls="$(cat $1 | grep __NR_ | sed -e 's/^.*__NR_//')"

exec > src/syscalls.rs

echo "// TODO: Remove dead_code"
echo "#[allow(dead_code, non_camel_case_types)]"
echo "#[derive(PartialEq, Eq, Clone, Copy, Debug)]"
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