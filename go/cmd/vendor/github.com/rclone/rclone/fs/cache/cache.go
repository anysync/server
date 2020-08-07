// Package cache implements the Fs cache
package cache

import (
	"sync"

	"github.com/rclone/rclone/fs"
	"github.com/rclone/rclone/lib/cache"
)

var (
	c     = cache.New()
	mu    sync.Mutex            // mutex to protect remap
	remap = map[string]string{} // map user supplied names to canonical names
)

// Lookup fsString in the mapping from user supplied names to
// canonical names and return the canonical form
func canonicalize(fsString string) string {
	mu.Lock()
	canonicalName, ok := remap[fsString]
	mu.Unlock()
	if !ok {
		return fsString
	}
	fs.Debugf(nil, "fs cache: switching user supplied name %q for canonical name %q", fsString, canonicalName)
	return canonicalName
}

// Put in a mapping from fsString => canonicalName if they are different
func addMapping(fsString, canonicalName string) {
	if canonicalName == fsString {
		return
	}
	mu.Lock()
	remap[fsString] = canonicalName
	mu.Unlock()
}

// GetFn gets an fs.Fs named fsString either from the cache or creates
// it afresh with the create function
func GetFn(fsString string, create func(fsString string) (fs.Fs, error)) (f fs.Fs, err error) {
	fsString = canonicalize(fsString)
	created := false
	value, err := c.Get(fsString, func(fsString string) (f interface{}, ok bool, err error) {
		f, err = create(fsString)
		ok = err == nil || err == fs.ErrorIsFile
		created = ok
		return f, ok, err
	})
	if err != nil && err != fs.ErrorIsFile {
		return nil, err
	}
	f = value.(fs.Fs)
	// Check we stored the Fs at the canonical name
	if created {
		canonicalName := fs.ConfigString(f)
		if canonicalName != fsString {
			fs.Debugf(nil, "fs cache: renaming cache item %q to be canonical %q", fsString, canonicalName)
			value, found := c.Rename(fsString, canonicalName)
			if found {
				f = value.(fs.Fs)
			}
			addMapping(fsString, canonicalName)
		}
	}
	return f, err
}

// Pin f into the cache until Unpin is called
func Pin(f fs.Fs) {
	c.Pin(fs.ConfigString(f))
}

// Unpin f from the cache
func Unpin(f fs.Fs) {
	c.Pin(fs.ConfigString(f))
}

// Get gets an fs.Fs named fsString either from the cache or creates it afresh
func Get(fsString string) (f fs.Fs, err error) {
	return GetFn(fsString, fs.NewFs)
}

// Put puts an fs.Fs named fsString into the cache
func Put(fsString string, f fs.Fs) {
	canonicalName := fs.ConfigString(f)
	c.Put(canonicalName, f)
	addMapping(fsString, canonicalName)
}

// Clear removes everything from the cache
func Clear() {
	c.Clear()
}
