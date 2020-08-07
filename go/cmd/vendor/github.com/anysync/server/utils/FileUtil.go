// Copyright (c) 2020, Yanbin (Henry) Zheng <ybzheng@gmail.com>
// All rights reserved.
//
// Use of this source code is governed by a AGPLv3 license that can be
// found in the LICENSE file.
package utils

import (
	"errors"
	"fmt"
	"github.com/golang/protobuf/proto"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"syscall"
	"time"
	"encoding/base64"
)

type ErrorCode uint32

const (
	// OK is returned on success.
	OK               ErrorCode = 0
	Canceled         ErrorCode = 1
	Unknown          ErrorCode = 2
	InvalidArgument  ErrorCode = 3
	DeadlineExceeded ErrorCode = 4
	NotFound         ErrorCode = 5
	AlreadyExists    ErrorCode = 6
	PermissionDenied ErrorCode = 7
	Unauthenticated  ErrorCode = 16
)

const (
	NEW_FILE_PERM = 0644
)

//var Log *zap.SugaredLogger

type FileInfo os.FileInfo
type FilesInfo []FileInfo

func (f FilesInfo) Len() int      { return len(f) }
func (f FilesInfo) Swap(i, j int) { f[i], f[j] = f[j], f[i] }

// GetFileInfo returns a FileInfo describing the named file
func GetFileInfo(name string) (FileInfo, error) {
	fi, err := os.Stat(name)
	return fi, err
}
func GetRealFileInfo(absPath string) (*RealFileInfo, error) {
	fi, err := os.Stat(absPath)
	if err != nil {
		Debugf("GetRealFileInfo.Err: %v\n", err)
		return nil, err
	}
	rfi := NewRealFileInfo(fi, absPath)
	return rfi, err
}

func IsDirectory(path string) bool {
	fi, err := os.Stat(path)
	if err != nil {
		return false
	}
	return fi.IsDir()
}

//Only returns true if it's an empty folder
func IsEmptyDirectory(path string) bool {
	fi, err := os.Stat(path)
	if err != nil {
		return false
	}
	if !fi.IsDir() {
		return false;
	}
	entries, err := ioutil.ReadDir(path)
	if err != nil {
		return false;
	}
	if len(entries) == 0{
		return true;
	}
	return false;
}

func IsSymlink(fileInfo FileInfo) bool {
	return fileInfo.Mode()&os.ModeSymlink != 0
}

// check the given file or directory exists or not
func FileExists(path string) bool {
	_, err := os.Stat(path)
	if err != nil {
		//Debugf("In FileExists. Error is %v\n", err)
		return false
	}
	return true
	//return !fi.IsDir()
}

// Basename returns the last element of P
func Basename(path string) string {
	return filepath.Base(path)
}

func Basename2(path string) string {
	p1 := filepath.Base(path)
	path = path[0: len(path) - len(p1) ]
	p2 := filepath.Base(path)
	return p2 + "/" + p1
}

// Dirname returns all but the last element of P, typically the P's directory
func Dirname(path string) string {
	return filepath.Dir(path)
}

// Extname returns the file Name extension used by P
func Extname(path string) string {
	return filepath.Ext(path)
}


// S return the S of the given filename.
// Returns 0 if the file does not exist or if the file S cannot be determined.
func FileSize(filename string) int64 {
	if fi, err := GetFileInfo(filename); err != nil {
		return 0
	} else {
		return fi.Size()
	}
}

// ModTimeUnix return the Last Modified Unix Timestamp of the given filename.
// Returns 0 if the file does not exist or if the file modtime cannot be determined.
func GetFileModTime(filename string) uint32 {

	if fi, err := GetFileInfo(filename); err != nil {
		return 0
	} else {
		Debugf("File :%s, mod time: %d\n", filename, fi.ModTime().Unix())
		return uint32(fi.ModTime().Unix())
	}
}

func SetFileModTime(filename string, modTimeInSeconds uint32) error {
	t := time.Unix(int64(modTimeInSeconds), 0)
	err := os.Chtimes(filename, t, t)
	return err
}

func SetCreateTime(filename string, t uint32) {
	//   http://stackoverflow.com/questions/33586980/how-to-set-the-creation-date-of-a-file-in-c-under-mac-os-x
	tm := int64(t) * int64(1000000000)
	utimes := make([]syscall.Timeval, 2)
	utimes[0] = syscall.NsecToTimeval(tm)
	utimes[1] = syscall.NsecToTimeval(tm)
	syscall.Utimes(filename, utimes)
}

//@time number of seconds that have passed since 1970-01-01T00:00:00
//Update file mod/create time, permission, and xattributes.
func UpdateFileMetaData(filename string, birthTime, modTimeInSeconds uint32, fileMode uint32, folderHash string, index uint32) error {
	key := CreateXattribKey(folderHash, index)
	xa, found := DbGetStringValue(key, false)
	if found {
		fattr := FileAttribs{}
		fattr.Attribs = make(map[string][]byte)
		if proto.Unmarshal([]byte(xa), &fattr) == nil {
			//if(json.Unmarshal([]byte(xa), &meta) == nil){
			for k, v := range fattr.Attribs {
				SetXattr(filename, k, v)
			}
		}
	}
	m := fileMode & 0x0FFFFFFF
	os.Chmod(filename, os.FileMode(m))

	//change birthTime first and then change modifiction time
	if birthTime != modTimeInSeconds {
		SetCreateTime(filename, birthTime)
	}

	t := time.Unix(int64(modTimeInSeconds), 0)
	err := os.Chtimes(filename, t, t)
	return err
}

// Mode return the FileMode of the given filename.
// Returns 0 if the file does not exist or if the file Mode cannot be determined.
func Mode(filename string) (os.FileMode, error) {
	if fi, err := GetFileInfo(filename); err != nil {
		return 0, err
	} else {
		return fi.Mode(), nil
	}
}

// Perm return the Unix permission bits of the given filename.
// Returns 0 if the file does not exist or if the file Mode cannot be determined.
func Perm(filename string) (os.FileMode, error) {
	if fi, err := GetFileInfo(filename); err != nil {
		return 0, err
	} else {
		return fi.Mode().Perm(), nil
	}
}

// Read reads the file named by filename and returns the contents.
func Read(filename string) ([]byte, error) {
	return ioutil.ReadFile(filename)
}

// ReadString reads the file named by filename and returns the contents as string.
func ReadString(filename string) (string, error) {
	buf, err := Read(filename)
	if err != nil {
		return "", err
	} else {
		return string(buf), nil
	}
}

func UpdateFile(filename string, seekOffset int64, data []byte) error {
	//Debug("Update file:", filename, "; offset: ", seekOffset, "; bytes.len: ", len(data))
	f, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE, NEW_FILE_PERM)
	if err != nil {
		return err
	}
	defer func() {
		f.Sync()
		f.Close()
	}()
	if seekOffset > 0 {
		f.Seek(int64(seekOffset), 0)
	}
	n, err := f.Write(data)
	if err == nil && n < len(data) {
		err = io.ErrShortWrite
	}

	return err
}

func UpdateFileSafe(filename string, seekOffset int64, data []byte) error {
	UpdateFile(filename, seekOffset, data)
	return nil
}

//Write bytes safely to a file for crash consistency.
func WriteBytesSafe(filename string, content []byte) error {
	MkdirAllForFile(filename)
	return DoWriteBytesSafe(filename, content)
}

// WriteString writes the contents of the string to filename.
func WriteString(filename, content string) error {
	return WriteBytesSafe(filename, []byte(content))
}

func AppendBytes(filename string, data []byte) error {
	dir := filepath.Dir(filename)
	if !FileExists(dir) {
		MkdirAll(dir)
	}

	f, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_APPEND, NEW_FILE_PERM)
	if err != nil {
		return err
	}
	defer func() {
		f.Sync()
		f.Close()
	}()
	n, err := f.Write(data)
	if err == nil && n < len(data) {
		err = io.ErrShortWrite
	}
	return err
}

/**
Append toAppendFileName to the filename
*/
func AppendFile(filename string, toAppendFileName string) error {
	dir := filepath.Dir(filename)
	if !FileExists(dir) {
		MkdirAll(dir)
	}

	f, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_APPEND, NEW_FILE_PERM)
	if err != nil {
		return err
	}
	defer f.Close()

	srcFile, err := os.OpenFile(toAppendFileName, os.O_RDONLY, 0)
	if err != nil {
		return err
	}
	defer srcFile.Close()
	_, err = io.Copy(f, srcFile)
	return err
}

/**
PACK file format:
PACK0001 - 8 Bytes
---
FileHash - 28 Bytes
FileSize - 4 Bytes
FileHash 1 Content   <=== from
---
FileHash - 28 Bytes
FileSize - 4 Bytes
FileHash 2 Content    <=== from
==============================

Extract file from pack file. from 'from' with size 'size', to the destFile.
*/
func ExtractFile(filename string, from int64, size int64, destFile string, encrypted bool, hash string, sharekey []string) error {
	f, err := os.OpenFile(filename, os.O_RDONLY, 0)
	if err != nil {
		Error("Couldn't open file:", filename)
		return err
	}
	defer f.Close()

	if from != 0 {
		f.Seek(from, 0)

	}
	originalDestFile := destFile;
	if(encrypted ) {destFile = destFile + "_"}
	dir := RemoveLastPathComponent(destFile);// RemoveLastUrlPathComponent(destFile)
	if !FileExists(dir) {
		MkdirAll(dir)
	}

	destF, err := os.OpenFile(destFile, os.O_WRONLY|os.O_CREATE|os.O_APPEND, NEW_FILE_PERM)
	if err != nil {
		Error("ExtractFile. Couldn't create file:", destFile)
		return err
	}
	_, err = io.CopyN(destF, f, size)
	destF.Close()


	if( err == nil && encrypted){
		var key [32]byte;
		if(sharekey == nil) {
			key, _ = GetFileEncKey(hash);
		}else{
			if buf, err := base64.StdEncoding.DecodeString(sharekey[0]) ; err == nil {
				bs := buf[0:HASH_BYTE_COUNT];
				if k, err := GetShareKey(fmt.Sprintf("%x", bs)); err == nil {
					//utils.Debug("ShareKey: ", fmt.Sprintf("%x", k), "; bs: ", fmt.Sprintf("%x", bs))
					bs :=  DecryptText(buf[ HASH_BYTE_COUNT:], &k)
					if (bs != nil) {
						copy(key[:], bs);
					}else{
						Debug("Couldn't decrypt dat's text")
					}
				}
			}
		}
		Debug("To decrypt file hash: ", hash, ". DestFile: ", originalDestFile)

		tmpFile := destFile + ".tlz"
		err = DecryptFile(destFile, tmpFile, &key)
		if err != nil {
			Debug("Decrypt err is ", err)
		} else {
			if err = RemoveFile(destFile); err != nil{
				Debug("Cannot remove file1:", destFile)
			}
			//Debug("Deleted: ", destFile)
			err = DecompressLz4(tmpFile, originalDestFile)
			if err = RemoveFile(tmpFile); err != nil {
				Debug("Cannot remove file2:", tmpFile)
			}
		}

	}
	return err
}

func CreateZeroLengthFile(filename string) {
	b := make([]byte, 0)
	AppendBytes(filename, b)
}

//// AppendContents appends the contents of the string to filename.
//// AppendContents is equivalent to AppendString.
//func AppendContents(filename, content string) error {
//	return AppendString(filename, content)
//}

// TempFile creates a new temporary file in the default directory for temporary files (see os.TempDir), opens the file for reading and writing, and returns the resulting *os.File.
func TempFile() (*os.File, error) {
	return ioutil.TempFile("", "")
}

// TempName creates a new temporary file in the default directory for temporary files (see os.TempDir), opens the file for reading and writing, and returns the filename.
func TempName() (string, error) {

	f, err := TempFile()
	if err != nil {
		return "", err
	}
	return f.Name(), nil

}

// Copy makes a copy of the file source to dest.
func CopyFile(source, dest string) (err error) {
	//return doCopyFile(source, dest)
	return EnsureFolderWritableAndCallFn(func() error {
		return doCopyFile(source, dest, false)
	}, dest)
}

func doCopyFile(source, dest string, hardlink bool) (err error) {
	if source == dest {
		return //no copy if src and dest are the same.
	}
	// checks source file is regular file
	sfi, err := GetFileInfo(source)
	if err != nil {
		return
	}
	if !sfi.Mode().IsRegular() {
		errors.New("cannot copy non-regular files.")
		return
	}

	// checks dest file is regular file or the same
	dfi, err := GetFileInfo(dest)
	if err != nil {
		if !os.IsNotExist(err) {
			return
		}
	} else {
		if os.SameFile(sfi, dfi) {
			return
		}
	}
	if hardlink {
		// hardlink source to dest
		err = os.Link(source, dest)
		if err == nil {
			return
		}
	}

	// cannot hardlink , copy contents
	in, err := os.Open(source)
	if err != nil {
		return
	}
	defer in.Close()

	out, err := os.Create(dest)
	if err != nil {
		return
	}
	defer out.Close()

	if _, err = io.Copy(out, in); err != nil {
		return
	}

	// syncing file
	err = out.Sync()

	// trying chmod destination file
	//err = out.Chmod(sfi.Mode())
	return
}

// Rename renames (moves) a file
func Rename(oldpath, newpath string) error {
	dir := filepath.Dir(newpath) // RemoveLastPathComponent(newpath);
	//Debugf("Rename. newpath:%s, fileName:%s\n", newpath, fileName);
	if !FileExists(dir) {
		MkdirAll(dir)
		//Debugf("To create all paths.\n")
	} else {
		if info, err := os.Stat(dir); err == nil && info.IsDir() && info.Mode()&0200 == 0 {
			os.Chmod(dir, 0755)
			defer os.Chmod(dir, info.Mode())
		}
	}

	// On Windows, make sure the destination file is writable
	if IsWindows() {
		os.Chmod(newpath, 0666)
		if !strings.EqualFold(oldpath, newpath) {
			err := os.Remove(newpath)
			if err != nil && !os.IsNotExist(err) {
				return err
			}
		}
	}

	return os.Rename(oldpath, newpath)
}

func RenameRecursively(directory, oldNameSuffix, newNameSuffix string){
	filepath.Walk(directory, func(path string, info os.FileInfo, err error) error {
		if(info == nil){
			return nil;
		}
		name := info.Name()
		if strings.HasSuffix(name, oldNameSuffix){
			Rename(path, filepath.Dir(path) + "/" + name[0:len(name)-len(oldNameSuffix)] + newNameSuffix);
		}
		return nil
	})
}

// RemoveFile removes the named file or directory.
func RemoveFile(name string) error {
	return os.Remove(name)
}

func RemoveFiles(names []string) {
	for _, name := range names {
		os.Remove(name)
	}
}

// RemoveAllFiles removes P and any children it contains.
func RemoveAllFiles(path string) error {
	return os.RemoveAll(path)
}

// Removes all children it contains, but keeps the directory
func RemoveAllSubItems(path string) error {
	if err := os.RemoveAll(path); err != nil {
		return err
	} else {
		return Mkdir(path)
	}
}

func RemoveEmptyFolders(absPath string, upLevel int) {
	if IsFolderEmpty(absPath) {
		Debugf("Local is empty : %s. To remove it.\n", absPath)
		RemoveFile(absPath)
		path := RemoveLastPathComponent(absPath)
		upLevel--
		if upLevel > 0 {
			RemoveEmptyFolders(path, upLevel)
		}
	}
}

// Unlink removes the named file or directory.
// Unlink is equivalent to RemoveFile.
func Unlink(name string) error {
	return os.Remove(name)
}

// Rmdir removes P and any children it contains.
// Rmdir is equivalent to RemoveAllFiles.
func Rmdir(path string) error {
	return os.RemoveAll(path)
}

// Mkdir creates a new directory with the specified Name and permission bits.
func Mkdir(name string) error {
	return os.Mkdir(name, os.ModePerm)
}

// MkdirAll creates a directory named P, along with any necessary parents.
func MkdirAll(path string) error {
	return os.MkdirAll(path, os.ModePerm)
}

func MkdirAllForFile(file string)error{
	dir := filepath.Dir(file)
	if !FileExists(dir) {
		return MkdirAll(dir)
	}
	return nil;
}

//// MkdirP creates a directory named P, along with any necessary parents.
//// MkdirP is equivalent to MkdirAll.
//func MkdirP(P string, perm os.FileMode) error {
//	return os.MkdirAll(P, perm)
//}

// Chmod changes the Mode of the named file to Mode.
func Chmod(name string, mode os.FileMode) error {
	return os.Chmod(name, mode)
}

// Chown changes the numeric uid and gid of the named file.
func Chown(name string, uid, gid int) error {
	return os.Chown(name, uid, gid)
}

// Find returns the FilesInfo([]FileInfo) of all files matching pattern or nil if there is no matching file. The syntax of patterns is the same as in Match. The pattern may describe hierarchical names such as /usr/*/bin/ed (assuming the Separator is '/').
func Find(pattern string) (FilesInfo, error) {

	matches, err := filepath.Glob(pattern)
	if err != nil {
		return nil, err
	}

	files := make(FilesInfo, 0)
	for _, f := range matches {
		fi, err := GetFileInfo(f)
		if err == nil {
			files = append(files, fi)
		}
	}
	return files, err
}

type byName struct{ FilesInfo }

type bySize struct{ FilesInfo }

type byModTime struct{ FilesInfo }

func (s byName) Less(i, j int) bool { return s.FilesInfo[i].Name() < s.FilesInfo[j].Name() }
func (s bySize) Less(i, j int) bool { return s.FilesInfo[i].Size() < s.FilesInfo[j].Size() }
func (s byModTime) Less(i, j int) bool {
	return s.FilesInfo[i].ModTime().Before(s.FilesInfo[j].ModTime())
}

// SortByName sorts a slice of files by filename in increasing order.
func (fis FilesInfo) SortByName() {
	sort.Sort(byName{fis})
}

// SortBySize sorts a slice of files by filesize in increasing order.
func (fis FilesInfo) SortBySize() {
	sort.Sort(bySize{fis})
}

// SortByModTime sorts a slice of files by file modified time in increasing order.
func (fis FilesInfo) SortByModTime() {
	sort.Sort(byModTime{fis})
}

// SortByNameReverse sorts a slice of files by filename in decreasing order.
func (fis FilesInfo) SortByNameReverse() {
	sort.Sort(sort.Reverse(byName{fis}))
}

// SortBySizeReverse sorts a slice of files by filesize in decreasing order.
func (fis FilesInfo) SortBySizeReverse() {
	sort.Sort(sort.Reverse(bySize{fis}))
}

// SortByModTimeReverse sorts a slice of files by file modified time in decreasing order.
func (fis FilesInfo) SortByModTimeReverse() {
	sort.Sort(sort.Reverse(byModTime{fis}))
}

// Exec runs the command and returns its standard output as string
func Exec(name string, arg ...string) (string, error) {
	cmd := exec.Command(name, arg...)
	out, err := cmd.Output()
	return string(out), err
}

var repositoryHashMap map[string][]byte

func GetRepositoryNameHash(repository string) []byte {
	var val []byte
	var ok bool
	if repositoryHashMap == nil {
		repositoryHashMap = make(map[string][]byte)
	}

	if val, ok = repositoryHashMap[repository]; !ok {
		val = Md5Bytes(repository)
		repositoryHashMap[repository] = val
	}
	return val
}

func GetSubFolders(path string) ([]os.FileInfo, error) {
	dir, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	return dir.Readdir(-1) //fis is already sorted by file Name
}

//return true if the path contains no file or directory
func IsFolderEmpty(path string) bool {
	dir, err := os.Open(path)
	if err != nil {
		return true
	}
	defer dir.Close()
	files, _ := dir.Readdirnames(1) //fis is already sorted by file Name
	return len(files) == 0

}

//Make sure the path is writable and call the fn
func EnsureFolderWritableAndCallFn(fn func() error, path string) error {
	dir := filepath.Dir(path)
	fi, err := os.Stat(dir)
	if err != nil {
		MkdirAll(dir);
		fi, err = os.Stat(dir)
	}
	if err == nil && fi.IsDir() {
		if fi.Mode()&0200 == 0 {
			err = os.Chmod(dir, 0755)
			if err == nil {
				defer func() {
					err = os.Chmod(dir, fi.Mode())
				}()
			}
		}
	}

	return fn()
}

func ExpandTilde(path string) string {
	if path == "~" {
		return getHomeDir()
	}

	path = filepath.FromSlash(path)
	if !strings.HasPrefix(path, fmt.Sprintf("~%c", os.PathSeparator)) {
		return path
	}

	home := getHomeDir()
	return filepath.Join(home, path[2:])
}

func getHomeDir() string {
	var home string

	switch runtime.GOOS {
	case "windows":
		home = filepath.Join(os.Getenv("HomeDrive"), os.Getenv("HomePath"))
		if home == "" {
			home = os.Getenv("UserProfile")
		}
	default:
		home = os.Getenv("HOME")
	}

	if home == "" {
		return ""
	}

	return home
}

//Return cleaned path, always in forward slash format.
func CleanPath(path string, toLowerCase bool) string {
	path = strings.ToLower(filepath.Clean(path))
	if IsWindows() { //on windows, after filepath.Clean(path), path (originally "Documents/api/test") becomes something like "Documents\api\test"
		path = strings.Replace(path, "\\", "/", -1)
	}
	if toLowerCase {
		path = strings.ToLower(path)
	}
	return path
}

//Returns total size of a directory (recursively)
func GetFolderSize(path string) (int64, error) {
	var size int64
	err := filepath.Walk(path, func(_ string, info os.FileInfo, err error) error {
		if !info.IsDir() {
			size += info.Size()
		}
		return err
	})
	return size, err
}

// CopyDir recursively copies a directory tree, attempting to preserve permissions.
// Source directory must exist, destination directory must *not* exist.
// Symlinks are ignored and skipped.
func CopyDir(src string, dst string) (err error) {
	src = filepath.Clean(src)
	dst = filepath.Clean(dst)

	si, err := os.Stat(src)
	if err != nil {
		return err
	}
	if !si.IsDir() {
		return fmt.Errorf("source is not a directory")
	}

	_, err = os.Stat(dst)
	if err != nil && !os.IsNotExist(err) {
		return
	}
	if err == nil {
		return fmt.Errorf("destination already exists")
	}

	err = os.MkdirAll(dst, si.Mode())
	if err != nil {
		return
	}

	entries, err := ioutil.ReadDir(src)
	if err != nil {
		return
	}

	for _, entry := range entries {
		srcPath := filepath.Join(src, entry.Name())
		dstPath := filepath.Join(dst, entry.Name())

		if entry.IsDir() {
			err = CopyDir(srcPath, dstPath)
			if err != nil {
				return
			}
		} else {
			// Skip symlinks.
			if entry.Mode()&os.ModeSymlink != 0 {
				continue
			}

			err = CopyFile(srcPath, dstPath)
			if err != nil {
				return
			}
		}
	}

	return
}
