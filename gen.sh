#!/bin/bash

go_dir=~/src/go
fake_goroot=$(mktemp -d)

cleanup_fake_goroot() {
	rm -r $fake_goroot
}


pre1_4() {
	[[ $(printf '%s\ngo1.4\n' "$1" | sort -V | head -n1) != go1.4 ]]
}

setup_fake_goroot() {
	rm -rf $fake_goroot
	mkdir -p $fake_goroot
	for dir in $(go env GOROOT)/*; do
		ln -s $dir $fake_goroot
	done
}

main() {
	setup_fake_goroot
	trap cleanup_fake_goroot EXIT
	export GOROOT="$fake_goroot"
	mkdir -p results

	for tag in $( cd $go_dir; git tag | grep -vE '(weekly|release|beta|rc)' | sort -V | grep -A 999 go1.14 ); do
		rm ${fake_goroot}/src
		root=${go_dir}/src$(pre1_4 $tag && echo /pkg)
		ln -s $root ${fake_goroot}/src

		echo $tag
		( cd $go_dir; git checkout $tag &>/dev/null )

		time env version=$tag ./go-api-parser $root results/${tag}.json || exit $?
	done
}

main
