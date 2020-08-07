// Copyright (c) 2020, Yanbin (Henry) Zheng <ybzheng@gmail.com>
// All rights reserved.
//
// Use of this source code is governed by a AGPLv3 license that can be
// found in the LICENSE file.
package utils

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
	"os"
	"strings"
)

type IndexBinRow struct {
	Index         uint32
	FileNameKey   string
	FileMode      uint32
	Timestamp     uint32
	CreateTime    uint32
	LastModified  uint32
	OperationMode uint8
	User          uint32
	FileSize      int64
	Offset        uint32
	Hash          []byte
	Name          string
	Raw           []byte
}

func GetRowByHash(fileName string, hash string) *IndexBinRow {
	hashBytes := FromHex(hash)
	file, err := os.Open(fileName)
	if err != nil {
		Warnf("getRowByHash. No file: %s\n", err)
		return nil
	}
	defer file.Close()
	buf := make([]byte, FILE_INFO_BYTE_COUNT*512)
	var io IndexBinRow
	readSize := 0
	for {
		readSize, err = file.Read(buf)
		if err != nil || readSize == 0 {
			break
		}
		var start uint32 = 0 //FILE_INFO_BYTE_COUNT;
		for start < uint32(readSize) {
			io.ReadBytes(buf, start)
			start += FILE_INFO_BYTE_COUNT
			if bytes.Compare(io.Hash, hashBytes) == 0 {
				io.Raw = make([]byte, FILE_INFO_BYTE_COUNT)
				copy(io.Raw, buf[start - FILE_INFO_BYTE_COUNT:start])
				return &io
			}
		}
	}
	return nil
}

func ReadBinAll(fileName string, storeRawBytes bool) []*IndexBinRow {
	return doReadBin(fileName, FILTER_NONE, false, storeRawBytes, nil)
}
func ReadBin(fileName string, filter int32, includes []uint32) []*IndexBinRow {
	return doReadBin(fileName, filter, true, false, includes)
}
func doReadBin(fileName string, filter int32, skipFirstRow bool, storeRaw bool, includes[]uint32) []*IndexBinRow {
	var list []*IndexBinRow
	f, err := os.Open(fileName)
	if err != nil {
		//Debugf("Readbin, file not found: %s\n", fileName)
		return list
	}
	defer f.Close()

	readSize := 0
	isFirstRow := true
	max := uint32( math.MaxUint32 );
	if(includes != nil){
		max = 0;
		for _, m := range includes{
			if(m > max){
				max = m;
			}
		}
	}
	for {
		buf := make([]byte, FILE_INFO_BYTE_COUNT*512)
		readSize, err = f.Read(buf)
		if err != nil || readSize == 0 {
			break
		}
		var start uint32 = 0 //FILE_INFO_BYTE_COUNT;
		for start < uint32(readSize) {
			var row = new(IndexBinRow)
			if storeRaw {
				row.Raw = make([]byte, FILE_INFO_BYTE_COUNT)
				copy(row.Raw, buf[start:start+FILE_INFO_BYTE_COUNT])
			}
			row.ReadBytes(buf, start)
			start += FILE_INFO_BYTE_COUNT
			if isFirstRow {
				isFirstRow = false
				if skipFirstRow {
					continue
				}
			}
			if filter == FILTER_NONE {
				list = append(list, row)
				continue
			}
			if IsFileModeDeleted(row.FileMode) {
				if filter == FILTER_DELETED_ONLY {
					list = append(list, row)
				}
				continue
			}
			isDir := IsFileModeDirectory(row.FileMode)
			if isDir && filter == FILTER_FILE_ONLY {
				continue
			}
			if !isDir && filter == FILTER_DIR_ONLY {
				continue
			}
			if(includes != nil){
				if(row.Index > max){
					break;
				}
				found := false;
				for _, m := range includes{
					if(m == row.Index){
						found = true;
						break;
					}
				}
				if(!found){
					continue;
				}
			}
			list = append(list, row)

		}
	}
	return list
}
func ReadBinFileForIndex(fileName string, index uint32) *IndexBinRow {
	f, err := os.Open(fileName)
	if err != nil {
		//Debug("ReadBinFileForIndex error: %s\n", err)
		return nil
	}
	defer f.Close()

	bufSize := FILE_INFO_BYTE_COUNT
	bs := make([]byte, bufSize)
	offset := index * FILE_INFO_BYTE_COUNT
	if offset > 0 {
		f.Seek(int64(offset), 0)
	}
	_, err = f.Read(bs)
	if err != nil {
		return nil
	}
	var row = new(IndexBinRow)
	row.ReadBytes(bs, 0)
	if row.Index == index {
		fname, foundKey := DbGetStringValue(row.FileNameKey, true) // items.get(row.FileNameKey)
		if foundKey {
			row.Name = fname
		}
	}

	return row
}

func (this IndexBinRow) WriteBytes(result []byte) {
	WriteBytes(result, this.Index, this.FileNameKey, this.CreateTime, this.FileMode, this.Timestamp,
		this.LastModified, this.FileSize, this.Hash, this.OperationMode, this.Offset)
}

func WriteBytes(bs []byte, index uint32, fileNameKey string, creationTime uint32,
	fileMode uint32, timestamp uint32, lastModified uint32, fileSize int64,
	shaHash []byte, opMode uint8,  offset uint32) {

	start := 0
	PutUint32(bs, start, index)

	start += 4

	fkey := FromHex(fileNameKey)
	//Debug("WriteBytes.fileNameKey: ", fileNameKey , "; len = ", len(fileNameKey))
	for i := 0; i < FILE_NAME_KEY_BYTE_COUNT; i++ {
		bs[i+start] = fkey[i]
	}
	start += FILE_NAME_KEY_BYTE_COUNT

	//var Offset uint32 = 0
	PutUint32(bs, start, offset)

	start += 4
	PutUint32(bs, start, creationTime)

	start += 4
	PutUint32(bs, start, fileMode)

	start += 4
	PutUint32(bs, start, timestamp)

	start += 4
	PutUint32(bs, start, lastModified)

	start += 4
	PutUint64(bs, start, uint64(fileSize)) // computeI64(FileSize, opMode))

	start += 8
	bs[start] = opMode
	start++
	config := LoadConfig()
	user := uint32(ToInt(config.User))
	PutUint32(bs, start, user)
	start += 4

	i := 0
	c := cap(bs)
	for start < c && i < HASH_BYTE_COUNT {
		bs[start] = shaHash[i]
		start++
		i++
	}
}

func WriteFolderRowBytes(bs []byte, index uint32, fileNameKey string, repoHash string, shaHash []byte, opMode uint8) {

	start := 0
	PutUint32(bs, start, index)

	start += 4

	fkey := FromHex(fileNameKey)
	for i := 0; i < FILE_NAME_KEY_BYTE_COUNT; i++ {
		bs[i+start] = fkey[i]
	}
	start += FILE_NAME_KEY_BYTE_COUNT

	fkey = FromHex(repoHash)
	for i := 0; i < FILE_NAME_KEY_BYTE_COUNT; i++ {
		bs[i+start] = fkey[i]
	}
	start += FILE_NAME_KEY_BYTE_COUNT

	bs[start] = opMode
	start++
	config := LoadConfig()
	user := uint32(ToInt(config.User))
	PutUint32(bs, start, user)
	start += 4

	i := 0
	c := cap(bs)
	for start < c && i < HASH_BYTE_COUNT {
		bs[start] = shaHash[i]
		start++
		i++
	}
}
func (row *IndexBinRow) ReadBytes(b []byte, start uint32) {
	//big-endian byte order is also referred to as network byte order.

	var s  = b[start : start+4]
	row.Index = binary.BigEndian.Uint32(s)

	start += 4
	s = b[start : start+FILE_NAME_KEY_BYTE_COUNT]
	row.FileNameKey = fmt.Sprintf("%x", s)

	start += FILE_NAME_KEY_BYTE_COUNT
	s = b[start : start+4]
	row.Offset = binary.BigEndian.Uint32(s)

	start += 4
	s = b[start : start+4]
	row.CreateTime = binary.BigEndian.Uint32(s)

	start += 4
	s = b[start : start+4]
	row.FileMode = binary.BigEndian.Uint32(s)

	start += 4
	s = b[start : start+4]
	row.Timestamp = binary.BigEndian.Uint32(s)

	start += 4
	s = b[start : start+4]
	row.LastModified = binary.BigEndian.Uint32(s)

	start += 4
	s = b[start : start+8]
	i64 := binary.BigEndian.Uint64(s)
	row.FileSize = int64(i64) // int64(i64 & 0x00FFFFFFFFFFFFFF)

	start += 8
	row.OperationMode = uint8(b[start])
	start++

	s = b[start : start+4]
	row.User = binary.BigEndian.Uint32(s)
	start += 4
	//MUST MAKE a copy otherwise it will cause memory problem.
	row.Hash = make([]byte, HASH_BYTE_COUNT)
	copy(row.Hash, b[start:start+HASH_BYTE_COUNT])
}

func (row IndexBinRow) ToString() string {
	return fmt.Sprintf("%d, %s, ts:%d, ct:%d, mt:%d, Size:%d, %s, %x", row.Index, row.FileNameKey, row.Timestamp, row.CreateTime, row.LastModified, row.FileSize, row.Name, row.Hash)
}
func (this IndexBinRow) ToHashString() string {
	return fmt.Sprintf("%x", this.Hash)
}

func GetFileMode(row []byte) uint32 {
	var fileMode uint32
	var s []byte = row[FILE_MODE_INDEX : FILE_MODE_INDEX+4]
	fileMode = binary.BigEndian.Uint32(s)
	Debugf("FileHash Mode is %d, row is %v\n", fileMode, row)
	return fileMode
}

func SetRowIndex(row[]byte, index uint32) []byte{
	PutUint32(row, 0, index)
	return  row;
}

func GetHashFromRowBytes(row []byte) string {
	blen := len(row)
	bs := row[blen-HASH_BYTE_COUNT : blen]
	return fmt.Sprintf("%x", bs)
}

func GetRowAt(fileName string, nth uint32) *IndexBinRow {
	var row IndexBinRow
	file, err := os.Open(fileName)
	if err != nil {
		//fmt.Fprintf(os.Stderr, "GetRowAt, FileName:%s. Cannot open file: %s\n", FileName, err)
		//debug.PrintStack()
		return nil
	}
	defer file.Close()

	if nth != 0 {
		file.Seek(int64(FILE_INFO_BYTE_COUNT*nth), 0)
	}
	buf := make([]byte, FILE_INFO_BYTE_COUNT)
	readCount := 0

	readCount, err = file.Read(buf)
	if err != nil || readCount == 0 {
		return nil
	}
	row.ReadBytes(buf, 0)
	row.Raw = buf;
	return &row
}
func GetRepoHashFromBinFile(fileName string) string {
	file, err := os.Open(fileName)
	if err != nil {
		//fmt.Fprintf(os.Stderr, "GetRowAt, FileName:%s. Cannot open file: %s\n", FileName, err)
		//debug.PrintStack()
		return ""
	}
	defer file.Close()

	buf := make([]byte, FILE_INFO_BYTE_COUNT)

	readCount, err := file.Read(buf)
	if err != nil || readCount == 0 {
		return ""
	}
	return GetRepoHash(buf)
}

func GetRepoHash(row []byte) string{
	start := FILE_OFFSET_INDEX
	s :=  row[start: start+FILE_NAME_KEY_BYTE_COUNT]
	return fmt.Sprintf("%x", s)
}

func GetFolderFullPath(folderHash string) string {
	var root string
	relativePath := GetFolderFullRelativePath(folderHash, &root)
	Debug("folderHash: ", folderHash , "; relPath: ", relativePath , "; root: ", root)
	if len(root) == 0 {
		return ""
	}
	if dir := GetRepositoryLocal(root, folderHash); dir != "" {
		return dir + "/" + relativePath
	}
	return ""
}

//	baseFileName := repoTreePath + "/" + HashToPath(folderHash)
func GetFolderFullRelativePath(folderHash string, root *string) string {
	var list []string
	shareFolder := GetFirstShareFolderOnClient(folderHash)
	if(shareFolder != nil && !IsShareFolderOwner(shareFolder)){
		return shareFolder.Name;
	}

	if !GetPathList(folderHash, nil, &list, root, 0, false) {
		return ""
	}
	if(len(list) == 0){
		return "/"
	}else {
		if(len(list) > 0) {list = list[1:];}
		return strings.Join(list, "/")
	}
}

func GetShareFolderRelativePath(shareFolder *ShareFolder, folderHash string, root *string,  rowIndex uint32)[]string{
	var list []string
	if(shareFolder != nil && !IsShareFolderOwner(shareFolder)){
		* root = ROOT_SHARE_NODE;
		baseFileName := GetTopTreeFolder() + HashToPath(folderHash)
		binFileName :=baseFileName+".bin"
		row := GetRowAt(binFileName, rowIndex)
		if(row != nil) {
			fileName, foundKey := DbGetStringValue(row.FileNameKey, true) // folder.get(FileNameKey)
			if foundKey {
				return []string{ROOT_SHARE_NODE, shareFolder.Name, fileName}; //GetTopShareFolder() + HashToPath(shareFolder.Hash) + "/" +
			}
		}
		return list;
	}
	return list;
}

//	baseFileName := repoTreePath + "/" + HashToPath(folderHash)
func GetFullRelativePath(folderHash,  fileHash string, root *string, rowIndex uint32) []string {
	if(GetHashSuffix() == "") {
		InitHashSuffix()
	}
	var list []string

	shareFolder := GetFirstShareFolderOnClient(folderHash)
	if(shareFolder != nil && ! IsShareFolderOwner(shareFolder)) {
		Debug("shareFolder is not nil. name: ", shareFolder.Name)
		list = GetShareFolderRelativePath(shareFolder, folderHash, root, rowIndex)
		Debug("List.size: ", len(list), "; list: ", list)
		return list
	}

	if !GetPathList(folderHash, &fileHash, &list,  root, rowIndex, false) {
		//it happens sometimes but it seems to be normal.
		//fmt.Fprintf(os.Stderr, "baseFile: %s, FileHash: %s; root: %s\n", baseFileName, fileHash, *root)
		return list
	}
	if(len(list) > 0) {list = list[1:];}
	return list
}

func GetPathList(folderHash string, fileHash *string, paths *[]string,  root *string, rowIndex uint32, getDirsOnly bool) bool {
	//Debug("EnterGetPathList. getDirsOnly: ", getDirsOnly, "; RowIndex: ", rowIndex,"; fileHash: ", * fileHash, ";  folderHash: ",   folderHash)
	baseFileName := GetTopTreeFolder() + HashToPath(folderHash)
	var fileNameKey, parentFileNameKey string;
	var parentFirstRow * IndexBinRow;
	binFileName :=baseFileName+".bin"
	if(getDirsOnly){
		parentFirstRow = GetRowAt(binFileName, 0);
	}else {
		if (rowIndex == 0) {
			parentFirstRow = getFileIndex(binFileName, fileHash, &fileNameKey)
			Debug("set file name 0 to :", fileNameKey)
		} else {
			var row *IndexBinRow;
			if(rowIndex == math.MaxUint32 && len(*fileHash) > 0){
				row = GetRowByHash(binFileName, *fileHash)
			}else {
				row = GetRowAt(binFileName, rowIndex)
			}
			if row == nil {
				Warn("GetPathList.GetRowAt returns nil !", "; rowIndex: ", rowIndex, "; binFile: ", binFileName)
				return true;
			}
			if (row.ToHashString() != *fileHash) {
				Debug("row.hash ", row.ToHashString(), " is not equal to filehash: ", * fileHash)
				*paths = nil;
				return false;
			}

			fileNameKey = row.FileNameKey
			Debug("set file name 1 to :", fileNameKey)
			parentFirstRow = GetRowAt(binFileName, 0)
		}
		if len(fileNameKey) == 0 {
			//Debugf("Error, filenamekey is empty. baseFile:%s; rowIndex:%d, fileHash: %s", baseFileName+".bin", rowIndex,  *fileHash)
			return false
		}
	}
	if(parentFirstRow == nil){
		Warn("GetPathList. parentFirstRow nil!", "; rowIndex: ", rowIndex, "; binFile: ", binFileName)
		os.Exit(1)
		return true;
	}
	parentHash := parentFirstRow.ToHashString()
	parentFileNameKey = parentFirstRow.FileNameKey;
	//Debugf("RowIndex:%d, ParentHash:%s; fileNameKey:%s, folderHash:%s, parentFirstRow:%x, binFileName: %s", rowIndex, parentHash, fileNameKey, folderHash, parentFirstRow, binFileName)
	if parentHash != NULL_HASH && parentHash != "" {
		if !GetPathList(parentHash, &folderHash, paths,  root, 0, true) {
			return false
		}
	}
	if(CurrentRepoMap == nil || len(CurrentRepoMap) == 0){
		InitRepoMap();
	}

	if name, ok := CurrentRepoMap[folderHash]; ok{
		Debug("Set root to ", name)
		*root = name;
	}

	if fileNameKey == NULL_HASH && root != nil {
		return true
	}

	fileName, foundKey := DbGetStringValue(parentFileNameKey, true) // folder.get(FileNameKey)
	if foundKey {
		*paths = append(*paths, fileName)
	} else {
		Debug("parentFileNameKey: ", parentFileNameKey, "; root: ", *root, "; Now paths:", *paths)
		return false
	}

	if(rowIndex > 0 && len(fileNameKey) > 0) {
		fileName, foundKey = DbGetStringValue(fileNameKey, true) // folder.get(FileNameKey)
		if foundKey {
			*paths = append(*paths, fileName)
		} else {
			Debug("FileNameKeyNotFound. FileNameKey: ", fileNameKey, "; root: ", *root, "; Now paths:", *paths)
			return false
		}
	}
	return true
}

//Get Index for the specified file with Hash
//@return the first row in IndexBinRow object.
//if the passed Hash is null, then it just returns the first row.
func getFileIndex(binFileName string, hash *string, fileNameKey *string) *IndexBinRow {
	var io, firstRow IndexBinRow
	var hashBytes []byte
	if hash != nil {
		hashBytes = FromHex(*hash)
	}
	file, err := os.Open(binFileName)
	if err != nil {
		//fmt.Fprintf(os.Stderr, "getFileIndex. No file: %s. Hash: %s\n", binFileName, *hash)
		return &firstRow
	}
	defer file.Close()
	buf := make([]byte, FILE_INFO_BYTE_COUNT*512)
	readSize := 0
	isFirst := true
	i := 0
	for {
		readSize, err = file.Read(buf)
		if err != nil || readSize == 0 {
			break
		}
		var start uint32 = 0 //FILE_INFO_BYTE_COUNT;
		for start < uint32(readSize) {
			io.ReadBytes(buf, start)
			start += FILE_INFO_BYTE_COUNT
			if isFirst {
				firstRow = io
				isFirst = false
				if hash == nil {
					*fileNameKey = io.FileNameKey
					return &firstRow
				}
			}
			if bytes.Compare(io.Hash, hashBytes) == 0 {
				*fileNameKey = io.FileNameKey
				return &firstRow
			}
			i++
		}
	}
	return &firstRow
}

type ReadServerBinFunc func(begin, end, timestamp uint32, hash string) error


func ReadServerBin(fileName string, f ReadServerBinFunc) {
	file, err := os.Open(fileName)
	if err != nil {
		return
	}
	defer file.Close()

	for {
		buf := make([]byte, SERVER_LOG_BIN_ROW_SIZE*512)
		readCount, err := file.Read(buf)
		if err != nil || readCount == 0 {
			break
		}
		start := 0
		for start < readCount {
			var s = buf[start : start+4]
			begin := binary.BigEndian.Uint32(s) //id
			start += 4

			s = buf[start : start+4]
			timestamp := binary.BigEndian.Uint32(s) //Timestamp
			start += 4

			s = buf[start : start+4]
			end := binary.BigEndian.Uint32(s)
			start += 4

			hash := buf[start : start+ HASH_BYTE_COUNT]
			start += +HASH_BYTE_COUNT
			sha := fmt.Sprintf("%x", hash)

			if err := f(begin, end, timestamp, sha); err != nil{
				return;
			}
		}
	}
}
