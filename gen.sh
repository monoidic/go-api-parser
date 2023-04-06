#!/bin/bash

go_dir=~/src/go
fake_goroot=/dev/shm/fake_goroot # mktemp -d

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
	export GOROOT="$fake_goroot" GOMAXPROCS=4

	for tag in $( cd ~/src/go/; git tag | grep -vE '(weekly|release|beta|rc)' | sort -V ); do
		rm -f ${fake_goroot}/src
		root=${go_dir}/src$(pre1_4 $tag && echo /pkg)
		ln -sf $root ${fake_goroot}/src

		echo $tag

		(
			cd ~/src/go/src
			git checkout $tag &>/dev/null
		)

		time ./go-api-parser $root results/${tag}.json || exit $?
	done
}

main
