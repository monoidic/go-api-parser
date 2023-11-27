package main

import (
	"fmt"
	"os"
	"strings"

	"golang.org/x/mod/semver"
)

// getArchitectures generates a list of architectures supported by the
// specific version of Go specified in the "version" environment variable.
// It covers Go versions from 1.1 up to 1.20, and for each version,
// it appends the architectures introduced in that version to the list.
//
// The function uses semantic versioning to compare Go versions. If the
// specified Go version is older than the version currently considered in the function,
// the function will not include the architectures introduced in and after the considered version.
//
// The list of architectures is constructed based on the Go release notes
// (https://go.dev/doc/devel/release), with a few exceptions marked with TODOs.
func getArchitectures() (out []string) {
	// TODO check ALL of this over
	out = []string{
		"darwin-amd64",
		"darwin-amd64-cgo",
		/*
			"freebsd-386",
			"freebsd-386-cgo",
			"freebsd-amd64",
			"freebsd-amd64-cgo",
		*/
		"linux-386",
		"linux-386-cgo",
		"windows-386",
		"windows-386-cgo",
		"windows-amd64",
		"windows-amd64-cgo",
		"linux-amd64",
		"linux-amd64-cgo",
		// should be fine above here
		// TODO track these down somehow
		/*"linux-ppc64",*/
		// // added in 1.11, but this is not going to be useful here
		//"js-wasm",
	}

	versionTable := []struct {
		version string
		archs   []string
	}{
		{
			// https://go.dev/doc/go1.1#platforms
			version: "v1.1",
			archs: []string{
				/*"freebsd-arm", "netbsd-386", "netbsd-386-cgo", "netbsd-amd64",
				"netbsd-amd64-cgo", "netbsd-arm", "netbsd-arm-cgo", "openbsd-386", "openbsd-386-cgo",
				"openbsd-amd64", "openbsd-amd64-cgo", "linux-arm", "linux-arm-cgo",
				*/
				"linux-arm", "linux-arm-cgo",
			}},
		{
			// ???
			version: "v1.2",
			archs:   []string{ /*"dragonfly-amd64", "dragonfly-amd64-cgo"*/ },
		},
		{
			// https://go.dev/doc/go1.3#os
			version: "v1.3",
			archs:   []string{ /*"plan9-386", "solaris-amd64"*/ },
		},
		{
			// https://go.dev/doc/go1.4#os
			version: "v1.4",
			archs:   []string{
				/*
					"android-arm", "android-arm-cgo", "plan9-amd64", "android-amd64",
					"android-amd64-cgo", "android-arm64", "android-arm64-cgo",
				*/
			},
		},
		{
			// https://go.dev/doc/go1.5#ports
			version: "v1.5",
			archs: []string{
				/*
					"darwin-arm64", "darwin-arm64-cgo", "linux-arm64",
					"linux-arm64-cgo", "linux-ppc64le", "linux-ppc64le-cgo", "solaris-amd64-cgo",
				*/
				"darwin-arm64", "darwin-arm64-cgo", "linux-arm64", "linux-arm64-cgo",
			},
		},
		{
			// https://go.dev/doc/go1.6#ports
			version: "v1.6",
			archs:   []string{
				/*
					"linux-mips64", "linux-mips64-cgo", "linux-mips64le", "linux-mips64le-cgo",
					"android-386", "android-386-cgo",
				*/
			},
		},
		{
			// https://go.dev/doc/go1.7#ports
			version: "v1.7",
			archs:   []string{ /*"linux-s390x", "linux-s390x-cgo", "plan9-arm"*/ },
		},
		{
			// https://go.dev/doc/go1.8#ports
			version: "v1.8",
			archs:   []string{ /*"linux-mips", "linux-mips-cgo", "linux-mipsle", "linux-mipsle-cgo"*/ },
		},
		{
			// ???
			version: "v1.11",
			archs:   []string{ /*"linux-riscv64"*/ },
		},
		{
			// https://go.dev/doc/go1.12#ports
			version: "v1.12",
			// go tool dist list -json | jq '.[] | select(.CgoSupported == false and .GOARCH == "ppc64")'
			// does linux-ppc64 support CGO or not?
			archs: []string{ /*"linux-ppc64-cgo", "windows-arm", "aix-ppc64", "openbsd-arm-cgo"*/ },
		},
		{
			// https://go.dev/doc/go1.13#ports
			version: "v1.13",
			archs:   []string{
				/*
					"aix-ppc64-cgo", "illumos-amd64", "illumos-amd64-cgo", "freebsd-arm-cgo",
					"netbsd-arm64", "netbsd-arm64-cgo", "openbsd-arm64", "openbsd-arm64-cgo",
				*/
			},
		},
		{
			// https://go.dev/doc/go1.14#ports
			version: "v1.14",
			archs:   []string{ /*"freebsd-arm64", "freebsd-arm64-cgo"*/ },
		},
		{
			// https://go.dev/doc/go1.15#ports
			version: "v1.15",
			archs:   []string{ /*"openbsd-arm"*/ },
		},
		{
			// https://go.dev/doc/go1.16#ports
			version: "v1.16",
			archs:   []string{
				/*"ios-arm64", "ios-arm64-cgo", "ios-amd64", "ios-amd64-cgo", "openbsd-mips64", "linux-riscv64-cgo",*/
			},
		},
		{
			// https://go.dev/doc/go1.17#ports
			version: "v1.17",
			archs:   []string{ /*"windows-arm64", "windows-arm64-cgo", "openbsd-mips64-cgo"*/ },
		},
		{
			// https://go.dev/doc/go1.19#ports
			version: "v1.19",
			archs:   []string{ /*"linux-loong64", "linux-loong64-cgo"*/ },
		},
		{
			// https://go.dev/doc/go1.20#ports
			version: "v1.20",
			archs:   []string{ /*"freebsd-riscv64", "freebsd-riscv64-cgo"*/ },
		},
		// wasip1-wasm added in 1.21, but not interesting here
	}

	version := "v" + goVersion[2:] // e.g go1.20.2 to v1.20.2

	for _, entry := range versionTable {
		if semver.Compare(version, entry.version) == -1 {
			return
		}

		out = append(out, entry.archs...)
	}

	return out
}

func getBuildConstraints() map[string]map[string]bool {
	out := make(map[string]map[string]bool, len(architectures))

	for _, architecture := range architectures {
		split := strings.Split(architecture, "-")
		archMap := make(map[string]bool)
		for _, tag := range split {
			archMap[tag] = true
			if unixOS[tag] {
				archMap["unix"] = true
			}
		}
		out[architecture] = archMap
	}

	return out
}

var filteredDirs = map[string]bool{
	"testdata": true,
	"vendor":   true,
	"cmd":      true,
	".git":     true,
}

// from github.com/golang/go src/go/build/syslist.go
var knownOS = []string{
	"aix",
	"android",
	"darwin",
	"dragonfly",
	"freebsd",
	"hurd",
	"illumos",
	"ios",
	"js",
	"linux",
	"nacl",
	"netbsd",
	"openbsd",
	"plan9",
	"solaris",
	"wasip1",
	"windows",
	"zos",
}

var knownOSSet = makeSet(knownOS)

var knownArch = []string{
	"386",
	"amd64",
	"amd64p32",
	"arm",
	"armbe",
	"arm64",
	"arm64be",
	"loong64",
	"mips",
	"mipsle",
	"mips64",
	"mips64le",
	"mips64p32",
	"mips64p32le",
	"ppc",
	"ppc64",
	"ppc64le",
	"riscv",
	"riscv64",
	"s390",
	"s390x",
	"sparc",
	"sparc64",
	"wasm",
}

var knownArchSet = makeSet(knownArch)

// from src/cmd/dist/build.go
var unixOS = map[string]bool{
	"aix":       true,
	"android":   true,
	"darwin":    true,
	"dragonfly": true,
	"freebsd":   true,
	"hurd":      true,
	"illumos":   true,
	"ios":       true,
	"linux":     true,
	"netbsd":    true,
	"openbsd":   true,
	"solaris":   true,
}

// parse os-arch[-cgo]
func getEnv(arch string) []string {
	out := os.Environ()
	if arch == "all" {
		return append(out, "GOARCH=amd64", "GOOS=linux", "CGO_ENABLED=0")
	}

	hasCGO := false
	for _, s := range strings.Split(arch, "-") {
		if knownArchSet.Contains(s) {
			out = append(out, fmt.Sprintf("GOARCH=%s", s))
		} else if knownOSSet.Contains(s) {
			out = append(out, fmt.Sprintf("GOOS=%s", s))
		} else if s == "cgo" {
			hasCGO = true
		} else {
			panic(arch)
		}
	}

	if hasCGO {
		out = append(out, "CGO_ENABLED=1")
	} else {
		out = append(out, "CGO_ENABLED=0")
	}

	return out
}
