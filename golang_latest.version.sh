#!/bin/bash

page=1
while true; do
    versions=$(curl -s "https://api.github.com/repos/golang/go/tags?per_page=100&page=${page}" | jq -r '.[].name')
    if [[ -z "$versions" || $(echo "$versions" | wc -l) != 100 ]]; then
        break
    fi
    echo "$versions"
    ((page++))
done | grep -vE '(weekly|release|beta|rc)' | sort -V | grep -A 999 go1.14 | tail -n1
