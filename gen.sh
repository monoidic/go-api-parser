#!/bin/bash

: ${go_dir:=~/src/go}
fake_goroot=$(mktemp -d)

cleanup_fake_goroot() {
	rm -r $fake_goroot
}

setup_fake_goroot() {
	rm -rf $fake_goroot
	mkdir -p $fake_goroot
	for dir in $(go env GOROOT)/*; do
		ln -s $dir $fake_goroot
	done
}

build_for_tag() {
	tag="$1"

	rm ${fake_goroot}/src
	root=${go_dir}/src
	ln -s $root ${fake_goroot}/src

	echo $tag
	git -C $go_dir checkout $tag &>/dev/null

	(
		for sum in $(find $root -name go.sum); do
			cd $(dirname $sum)
			go mod download
		done
	)

	time ./go-api-parser -get_cgo -src=$root -out=results/${tag}.json -version=$tag || exit $?
}

main() {
	# ensure latest code is being used
	GOEXPERIMENT=rangefunc go build
	setup_fake_goroot
	trap cleanup_fake_goroot EXIT
	export GOROOT="$fake_goroot"
	mkdir -p results

	if [[ -z $tag ]]; then
		for tag in $( git -C $go_dir tag | grep -vE '(weekly|release|beta|rc)' | sort -V | grep -A 999 go1.14 ); do
			build_for_tag $tag
		done
	else
		build_for_tag $tag
	fi
}

main
