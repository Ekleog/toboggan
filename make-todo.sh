#!/usr/bin/env bash

filelist="asker.sh Cargo.toml examples gen-syscalls.sh README.md src tests"

comm -23 <(grep -R TODO $filelist | grep -Ev '^Binary file ' | sort) <(cat TODO | sort) >> TODO
