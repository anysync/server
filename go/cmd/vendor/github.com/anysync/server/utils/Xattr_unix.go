// +build !windows

package utils

import (
	"github.com/pkg/xattr"
)

func GetXattr(path, name string) ([]byte, error) {
	b, e := xattr.Get(path, name)
	return b, e
}

func ListXattr(path string) ([]string, error) {
	s, e := xattr.List(path)
	return s, e
}

func SetXattr(path, name string, data []byte) error {
	e := xattr.Set(path, name, data)
	return e
}

func GetAllXattrs(path string) map[string][]byte {
	var list []string
	var err error
	if list, err = xattr.List(path); err != nil {
		Debug("Error")
	}
	var ret map[string][]byte
	for _, item := range list {
		var data []byte
		if data, err = xattr.Get(path, item); err != nil {
			Debug("Error")
		}
		if item == "com.apple.quarantine" {
			continue
		}

		if ret == nil {
			ret = make(map[string][]byte)
		}
		ret[item] = data
	}

	return ret
}
