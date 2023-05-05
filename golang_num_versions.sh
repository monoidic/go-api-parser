#!/bin/bash

page=1
while true; do
    versions=$(curl -s "https://api.github.com/repos/golang/go/tags?per_page=100&page=${page}" | jq -r '.[].name')
    echo "$versions"
    if [[ $(echo "$versions" | wc -l) != 100 ]]; then
        break
    fi
    ((page++))
done | grep -vE '(weekly|release|beta|rc)' | grep -A 999 go1.14 | wc -l
