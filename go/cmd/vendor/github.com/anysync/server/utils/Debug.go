
package utils

// https://dave.cheney.net/2014/09/28/using-build-to-switch-between-debug-and-release
// go test -tags release -integration -v -run=Lstat
//When -tags release is not present, the version from Release.go takes effect.
const (
	DEBUG = true
	TEST = false
)
