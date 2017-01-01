#!/usr/bin/env bash

comm -23 <(grep -R TODO src | grep -Ev '^Binary file ' | sort) <(cat TODO | sort) >> TODO
