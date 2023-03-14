#!/bin/bash

go_dir="${HOME}/src/go"
maxver=20
# concatenate all signatures together, and preprocess:
# filter out empty lines, comment lines, const/global variable definitions, struct fields, interface methods, and deprecation notices
# + remove comments at the end of lines
# remove lines: empty, full-line comment, const/var, deprecation, generic function/type/method
# remove content: struct fields, interface methods (not all are defined on their own?), end-of-line comments
# replace type parameter $0 with T

filter() {
    #sed -E '/^$/d;/^#/d;/, (const|var) /d;/\/\/deprecated/d;/, type [^ ]* (struct|interface),/d;s/#.*//' | sort -u
    sed -E '/^$/d;/^#/d;/, (const|var) /d;/\/\/deprecated/d;/\$0/d;s/(, type [^ ]* (struct|interface))(, .*| \{ .*)/\1/;s//\1/;s/#.*//' # | sort -u
}

order_uniq() {
    python3 -c '\
import sys
d = {}
for line in sys.stdin:
  d[line.rstrip()] = None
for line in d:
  print(line)'
}

(
    cat "${go_dir}"/api/go1.txt | filter
    for i in $(seq 1 $maxver); do
        cat "${go_dir}"/api/go1.${i}.txt | filter
    done

    # hacky workarounds...
    echo "pkg unsafe, type Pointer struct"
    echo "pkg testing, type testDeps struct"
) | order_uniq > api.txt