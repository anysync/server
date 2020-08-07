// +build windows

package utils

func GetXattr(path, name string) ([]byte, error) {
	return nil, nil
}

func ListXattr(path string) ([]string, error) {
	return nil, nil
}

func SetXattr(path, name string, data []byte) error {
	return nil
}

func GetAllXattrs(path string) map[string][]byte {
	return nil
}
