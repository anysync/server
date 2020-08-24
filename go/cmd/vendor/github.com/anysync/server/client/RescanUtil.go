// Copyright (c) 2020, Yanbin (Henry) Zheng <ybzheng@gmail.com>
// All rights reserved.
//
// Use of this source code is governed by a AGPLv3 license that can be
// found in the LICENSE file.
package client

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/panjf2000/ants"
	"golang.org/x/sync/syncmap"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	utils "github.com/anysync/server/utils"
)

func InitClient() {
	utils.InitHashSuffix()
	RcloneInit()
}
func init(){
	utils.SPECIAL_CHARS = make(map[byte]byte)

	for key, val := range utils.ESCAPE_CHARS {
		if val == '.' {
			continue
		} //'.' is special char only when it's the last char of a filename.
		utils.SPECIAL_CHARS[val] = key
	}
}
func UpdateBinFile(binFileName string, index uint32, fileMode uint32, repoHash, folderHash string, list map[string][]*utils.ModifiedRow, tasks *[]*utils.WriteTask, rowCount uint32) {
	utils.Debugf("To add UpdateBinFile for file:%s, Index:%d\n", binFileName, index)
	io := utils.GetRowAt(binFileName, index)
	io.FileMode = fileMode
	io.Offset = rowCount
	array := make([]byte, utils.FILE_INFO_BYTE_COUNT)
	io.WriteBytes(array)

	if(tasks != nil) {
		CreateUpdateRowTask(tasks, repoHash, folderHash, index, array, nil, io.FileNameKey, "", "", "")
	}
	mrow := utils.NewModifiedRow(false)
	mrow.Row = array
	mrow.OperationMode = utils.MODE_REINSTATE_DIRECTORY
	if rows, ok := list[folderHash]; ok {
		rows = append(rows, mrow)
		list[folderHash] = rows
	} else {
		rows = make([]*utils.ModifiedRow, 1)
		rows[0] = mrow
		list[folderHash] = rows
	}
}


func createFolderRow(repoHash, parentSha , fileNameKey string) []byte {
	bindDataArray := make([]byte, utils.FILE_INFO_BYTE_COUNT)
	var shaHash []byte
	shaHash = utils.FromHex(parentSha)
	utils.Debug("parentSha:" , parentSha, "; fileNameKey: ", fileNameKey, "; array.len: ", len(bindDataArray), "; Hash.len:",  len(shaHash))
	utils.WriteFolderRowBytes(bindDataArray, 0, fileNameKey, repoHash, shaHash, utils.MODE_UNKNOWN)
	return bindDataArray
}
func createRowWithHash(index, fileMode uint32, fileNameKey, hash string) []byte {
	bindDataArray := make([]byte, utils.FILE_INFO_BYTE_COUNT)
	shaHash := utils.FromHex(hash)
	utils.Debugf("array.len: %d, Hash.len:%d\n", len(bindDataArray), len(shaHash))
	now := uint32(time.Now().Unix())
	utils.WriteBytes(bindDataArray, index, fileNameKey, now, fileMode, now, now, 0, shaHash, utils.MODE_UNKNOWN, 0)
	return bindDataArray
}

func renameLocalCopy(repoTreePath, folderHash, fileHash string, rowIndex uint32, oldName string) {
	baseFileName := repoTreePath + "/" + utils.HashToPath(folderHash)
	var root string
	utils.Debugf("Enter renameLocalCopy. baseFile: %s, FileHash: %s\n", baseFileName, fileHash)
	list := utils.GetFullRelativePath(folderHash,  fileHash, &root, rowIndex)
	if list == nil || len(list) == 0 {
		fmt.Fprintf(os.Stderr, "renameLocalCopy. baseFile: %s, fileHash: %s\n", baseFileName, fileHash)
		return
	}
	var relativePath string;
	fileName := list[len(list)-1]
	shareFolder := utils.GetFirstShareFolderOnClient(folderHash)
	if(shareFolder == nil || utils.IsShareFolderOwner(shareFolder)) {
		relativePath = strings.Join(list, "/")
	}

	if dir := utils.GetRepositoryLocal(root, folderHash); dir != "" {
		var dest string;
		if( relativePath == ""){
			dest = dir + "/" + fileName;
		}else {
			dest = dir + "/" + relativePath
		}
		dir := filepath.Dir(dest);
		oldName = dir + "/" + oldName;
		if utils.FileExists(oldName) {
			utils.Debug("To rename file: ", oldName, " to ", dest)
			utils.Rename(oldName, dest)
		}
	}
}

func deleteLocalCopy(repoTreePath, folderHash, fileHash string, rowIndex uint32) {
	baseFileName := repoTreePath + "/" + utils.HashToPath(folderHash)
	var root string
	list := utils.GetFullRelativePath(folderHash,  fileHash, &root, rowIndex)

	if list == nil || len(list) == 0 {
		fmt.Fprintf(os.Stderr, "deleteLocalCopy. baseFile: %s, fileHash: %s\n", baseFileName, fileHash)
		return
	}
	var relativePath string;
	fileName := list[len(list)-1]
	shareFolder := utils.GetFirstShareFolderOnClient(folderHash)
	if(shareFolder == nil || utils.IsShareFolderOwner(shareFolder)) {
		relativePath = strings.Join(list, "/")
	}
	if dir := utils.GetRepositoryLocal(root, folderHash); dir != "" {
		var dest string;
		if( relativePath == ""){
			dest = dir + "/" + fileName;
		}else {
			dest = dir + "/" + relativePath
		}

		utils.Debug("deletelocalcopy, dest: ", dest)
		if utils.IsDirectory(dest) {
			err:=os.Remove(dest);//only remove empty folder; it doesn't remove if folder is not empty
			utils.Debug("To delete directory: ", dest, "; error is ", err)
		} else {
			if utils.FileExists(dest) {
				utils.Debug("To delete file: ", dest)
				utils.RemoveFile(dest)
			}
		}
	}
}

func updateLocalCopy(folderHash, binFileName, fileHash string, rowIndex uint32, isDirectory, isDeleted , isSizeZero bool ) error {
	if(isDeleted){
		utils.Debug("deleted. folder: ", folderHash, "; fileHash: ", fileHash)
		//todo ?
		return nil;
	}
	config := utils.LoadConfig() // properties.LoadFile(APP_CONFIG_FILE, properties.UTF8)
	if(config.Mode == utils.CONFIG_MODE_NEW_ONLY){
		return nil;
	}
	var root string
	subPath := utils.HashToPath(fileHash)
	if !isDirectory && !isSizeZero {
		if err := CopyObjectFromServer(fileHash); err != nil {
			utils.Debug("Couldn't copy obj from server")
			return err;
		}else{
			utils.Debug("Copied object from server for fileHash: ", fileHash)
		}
	}
	list :=  utils.GetFullRelativePath(folderHash,  fileHash, &root, rowIndex)
	if list == nil || len(list) == 0 || root == "" {
		utils.Infof("Some files not ready. updateLocalCopy. baseFile: %s, FileHash:%s, root: %s", binFileName, fileHash, root)
		return errors.New("cannot get relative path");
	}
	var relativePath string;
	shareFolder := utils.GetFirstShareFolderOnClient(folderHash)
	if(shareFolder == nil || utils.IsShareFolderOwner(shareFolder)){
		relativePath = strings.Join(list, "/")
	}
	if(strings.HasPrefix(relativePath, "docs/")){
		utils.Debug("Error relativePath")
		os.Exit(1);
	}
	fileName := list[len(list)-1]
	isWindows := utils.IsWindows()
	if dir := utils.GetRepositoryLocal(root, folderHash); dir != "" {
		utils.Debug("GetRepoLocal returns ", dir)
		var dest string
		changed := false
		io := GetRowByHash(binFileName, fileHash)
		if isWindows {
			wName, _, b := fixFileNameForWindows(fileName, io.Index, true)
			changed = b
			if changed {
				list[len(list)-1] = wName
				relativePath = strings.Join(list, "/")
			}
		}
		if( relativePath == ""){
			dest = dir + "/" + fileName;
		}else {
			dest = dir + "/" + relativePath
		}
		if !isWindows || !changed {
			fName, modTime, fsize := GetFileNameModTimeAndSize(dest)
			utils.Debugf("dest is %s, modTime: %d", dest, modTime)
			if modTime > 0 { //if file exists, then modTime > 0
				nameChanged := false
				utils.Debugf("fileName:%s, fName:%s", fileName, fName)
				if fName != fileName {
					fileName, nameChanged = fixDuplicateFileName(fileName, io.Index)
					utils.Debug("Now file name becomes ", fileName)
					list[len(list)-1] = fileName
					relativePath = strings.Join(list, "/")
					dest = dir + "/" + relativePath
				}

				//if the file doesn't change, don't update it, otherwise file modified time will change.
				if !nameChanged && io != nil && io.LastModified == modTime && io.FileSize == fsize {
					//because it only checks time and size, it's not accurate. Sometimes it may cause problem.
					utils.Debug("skip copy and return. dest: ", dest, "; FileExist: ", utils.FileExists(dest));
					return nil
				}
			}
		}
		if(isDirectory){
			utils.MkdirAll(dest);
		}else {
			if !isSizeZero {
				localFile := utils.GetTopObjectsFolder() + subPath + utils.EXT_OBJ
				utils.Debugf("in updatelocalcopy, local:%s, dest:%s\n", localFile, dest)
				utils.Debugf("Copy file1, src: %s, dest:%s\n", localFile, dest)
				if err := utils.CopyFile(localFile, dest); err != nil {
					return err;
				}
			}else{
				utils.CreateZeroLengthFile(dest);
			}
			utils.UpdateFileMetaData(dest, io.CreateTime, io.LastModified, io.FileMode, folderHash, io.Index)
		}
	}else{
		utils.Debug("GetRepoLocal returns empty dir")
	}
	return nil
}

// ModTimeUnix return the Last Modified Unix Timestamp of the given filename.
// Returns 0 if the file does not exist or if the file modtime cannot be determined.
func GetFileNameModTimeAndSize(filename string) (string, uint32, int64) {
	if fi, err := utils.GetFileInfo(filename); err != nil {
		return "", 0, 0
	} else {
		if utils.IsLinux() { //case sensitive, so return directly.
			return fi.Name(), uint32(fi.ModTime().Unix()), fi.Size()
		}
		//Note: Cannot use fileinfo.Name() directly, because if file exists, it just
		//returns the exact same name passed to this function, and don't reflect the real case of the file
		lower := strings.ToLower(fi.Name())
		dirPath := filepath.Dir(filename)
		dir, _ := os.Open(dirPath)
		defer dir.Close()
		fis, _ := dir.Readdir(-1) //fis is already sorted by file Name
		for _, fileInfo := range fis {
			if fileInfo.IsDir() {
				continue
			}
			if strings.ToLower(fileInfo.Name()) == lower {
				return fileInfo.Name(), uint32(fileInfo.ModTime().Unix()), fileInfo.Size()
			}
		}
		return fi.Name(), uint32(fi.ModTime().Unix()), fi.Size()
	}
}

func updateFileNameKeyAt(binFileName string, Index int, fileNameKey string) error {
	f, err := os.OpenFile(binFileName, os.O_RDWR, utils.NEW_FILE_PERM)
	if err != nil {
		return err
	}
	defer f.Close();

	pos := Index * utils.FILE_INFO_BYTE_COUNT

	binFileSize := utils.FileSize(binFileName)
	if pos > int(binFileSize + utils.FILE_INFO_BYTE_COUNT) {
		utils.Debugf("Error: Offset is too big. pos:%d, utils.FileSize:%d\n", pos, binFileSize)
		return errors.New("offset is too big")
	}

	pos += 4; //the index part
	f.Seek(int64(pos), 0)

	fileArray := utils.FromHex(fileNameKey)
	f.Write(fileArray)

	return err
}

func updateRowAt( binFileName string, index uint32, fileNameKey string, fileInfo *utils.RealFileInfo,  hash *string, dirFileMode uint32, opMode uint8) []byte {
	var newRowBytes []byte
	utils.Debugf("Enter updateRowAt binFile:%s, Index:%d, opMode:%d\n", binFileName, index, opMode)
	f, err := os.OpenFile(binFileName, os.O_RDWR, utils.NEW_FILE_PERM)
	if err != nil {
		utils.Warn("Error open file")
		return newRowBytes
	}
	defer f.Close()

	pos := index * utils.FILE_INFO_BYTE_COUNT
	binFileSize := utils.FileSize(binFileName)
	if pos >= uint32(binFileSize) {
		utils.Debugf("Error: Offset is too big. pos:%d, utils.FileSize:%d\n", pos, binFileSize)
		return newRowBytes
	}
	if pos > 0 {
		f.Seek(int64(pos), 0)
	}

	array := make([]byte, utils.FILE_INFO_BYTE_HEADER_COUNT)
	f.Read(array)
	fileArray := utils.FromHex(fileNameKey)
	for i := 4; i < 4+utils.FILE_NAME_KEY_BYTE_COUNT; i++ {
		array[i] = fileArray[i-4]
	}
	newDataSize := 25 + utils.HASH_BYTE_COUNT
	newData := make([]byte, newDataSize)
	currentTime := uint32(time.Now().Unix())
	if fileInfo != nil {
		utils.PutUint32(newData, 0, fileInfo.Permission) //Mode
		utils.PutUint32(newData, 4, currentTime)
		utils.PutUint32(newData, 8, fileInfo.LastModified)
		utils.PutUint64(newData, 12, uint64(fileInfo.Size))
	} else {
		if dirFileMode != 0 {
			fileMode := utils.SetFileModeDeleted(dirFileMode)
			utils.PutUint32(newData, 0, fileMode) //Mode
		} else {
			utils.PutUint32(newData, 0, utils.TYPE_DELETED_FILE) //Mode
		}
		utils.PutUint32(newData, 4, currentTime)
		utils.PutUint32(newData, 8, currentTime)
		utils.PutUint64(newData, 12, uint64(0))
	}
	newData[20] = opMode
	config := utils.LoadConfig()
	utils.PutUint32(newData, 21, utils.ToUint32(config.User))
	start := 25
	var hashBytes []byte
	if hash == nil {
		hashBytes = utils.FromHex(utils.NULL_HASH)
	} else {
		hashBytes = utils.FromHex(*hash)
	}
	for i := start; i < newDataSize; i++ {
		newData[i] = hashBytes[i-start]
	}
	newRowBytes = append(array, newData...)
	if hash != nil {
		utils.Debugf("updateRow. Hash:%s, newRowBytes.len: %d, newData.len:%d, array.len:%d\n", *hash, len(newRowBytes), len(newData), len(array))
	}
	utils.Debugf("To return from updateRowAt, newRow.len:%d\n", len(newRowBytes))
	return newRowBytes
}

func updateRowAtWithBytesNoAppendLog(folderHash, base string, index uint32, newRowBytes []byte, appendIfNotExists bool, attribs map[string][]byte) {
	fileName := base + ".bin"
	if !appendIfNotExists && int64(index*utils.FILE_INFO_BYTE_COUNT) >= utils.FileSize(fileName) {
		return
	}
	if len(newRowBytes) != utils.FILE_INFO_BYTE_COUNT {
		log.Panic(fmt.Sprintf("Wrong Bytes length: %d. FileHash: %s, Index: %d", len(newRowBytes), fileName, index))
	}
	utils.WriteFileInfoBin(base, int64(index*utils.FILE_INFO_BYTE_COUNT), newRowBytes)
	if(attribs != nil){

		utils.UpdateAttribs(true, "", folderHash, index, attribs);
		if(folderHash == utils.NULL_HASH){
			utils.Debug("Received row update with attrib. to update repo list.")
		}
	}
}

func updateRowAtWithBytes(base string, index uint32, newRowBytes []byte, appendIfNotExists bool) {
	fileName := base + ".bin"
	if !appendIfNotExists && int64(index*utils.FILE_INFO_BYTE_COUNT) >= utils.FileSize(fileName) {
		utils.Debug("return here, file size is ", utils.FileSize(fileName), ", index is ", index)
		return
	}
	if len(newRowBytes) != utils.FILE_INFO_BYTE_COUNT {
		log.Panic(fmt.Sprintf("Wrong Bytes length: %d. FileHash: %s, Index: %d", len(newRowBytes), fileName, index))
	}

	WriteAndAppendLog( base, newRowBytes, int64(index*utils.FILE_INFO_BYTE_COUNT), false, false)
}

func WriteAndAppendLog( base string, rows []byte, position int64, isCreateNewFile bool, isAppend bool) {
	//the logIndex in the rows appended to the log is the old Index; the logIndex inserted to the bin file
	//is the last rows Index of the log file.
	fileName := base + ".bin"
	logWriter := utils.NewMetaBinIO(base, true)
	binWriter := utils.NewMetaBinIO(base, false)
	if isAppend {
		binWriter.Append(rows) //AppendBytesSafe(fileName, rows);
		logWriter.Append(rows) //appendLog(fileName, logRows);
	} else {
		if isCreateNewFile {
			utils.WriteBytesSafe(fileName, rows)
		} else {
			if(position == utils.FileSize(fileName)){
				binWriter.Append(rows) //AppendBytesSafe(fileName, rows);
			}else {
				binWriter.Update(position, rows)
			}
		}
		logWriter.Append(rows)
	}
}

func DeleteAllItems(fileName string, folderHash string, deletedFiles map[string][]*DeletedRowData, taskList *[]*utils.WriteTask, logRowCount uint32) {
	var newRowBytes []byte
	file, err := os.Open(fileName)
	defer file.Close();
	if err != nil {
		utils.Debugf("DeleteAllItems. No file: %s\n", fileName)
		return
	}
	var io utils.IndexBinRow
	readSize := 0
	oneRow := make([]byte, utils.FILE_INFO_BYTE_COUNT)
	//todo: the following is not memory efficient. Change to read and write (to log and another bin) at the same time.
	for {
		buf := make([]byte, utils.FILE_INFO_BYTE_COUNT*512)
		readSize, err = file.Read(buf)
		if err != nil || readSize == 0 {
			break
		}
		var start uint32 = 0 //FILE_INFO_BYTE_COUNT;
		for start < uint32(readSize) {
			//utils.Debugf("To read buf, startRescan:%d\n", startRescan);
			io.ReadBytes(buf, start)
			start += utils.FILE_INFO_BYTE_COUNT
			mode := io.FileMode
			if !utils.IsFileModeDeleted(mode) {
				if utils.IsFileModeRegularFile(mode) {
					io.FileMode = utils.SetFileModeDeleted(io.FileMode) //TYPE_DELETED_FILE;
					if deletedFiles != nil {
						var data = new(DeletedRowData)
						data.folderHash = folderHash
						data.binFilePath = fileName
						data.hash = io.ToHashString()
						data.notToUpdateRow = true
						data.index = io.Index
						if t, found := deletedFiles[data.hash]; found {
							t = append(t, data)
							deletedFiles[data.hash] = t;
						}else {
							deletedFiles[data.hash] = []*DeletedRowData{data}
						}
					}
					io.OperationMode = utils.MODE_DELETED_FILE
					io.FileSize = 0
					utils.Debugf("Del file and set to NULL Hash: %s, folderHash:%s\n", fileName, folderHash)
				} else {
					io.FileMode = utils.SetFileModeDeleted(io.FileMode) //TYPE_DELETED_DIRECTORY;
				}
				io.Offset = logRowCount
			}

			io.WriteBytes(oneRow)
			newRowBytes = append(newRowBytes, oneRow...)
		}
	}
	if taskList != nil {
		*taskList = append(*taskList, createWriteBinTask(folderHash, newRowBytes))
	}
}

func GetRowByHash(fileName string, hash string) *utils.IndexBinRow {
	hashBytes := utils.FromHex(hash)
	file, err := os.Open(fileName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "GetRowByHash. No file: %s\n", err)
		return nil
	}
	defer file.Close()
	buf := make([]byte, utils.FILE_INFO_BYTE_COUNT*512)
	var io utils.IndexBinRow
	readSize := 0
	for {
		readSize, err = file.Read(buf)
		if err != nil || readSize == 0 {
			break
		}
		var start uint32 = 0 //FILE_INFO_BYTE_COUNT;
		for start < uint32(readSize) {
			io.ReadBytes(buf, start)
			start += utils.FILE_INFO_BYTE_COUNT
			if bytes.Compare(io.Hash, hashBytes) == 0 {
				return &io
			}
		}
	}
	return nil
}


//fileName is bin file's Name
func appendLog(fileName string, newRowBytes []byte) {
	fileName = strings.Replace(fileName, ".bin", ".log", 1)
	utils.AppendBytes(fileName, newRowBytes)
}

func ReverseReadLogFileForIndex(fileNameBase string, index uint32, from int, maxNumber int) ([]utils.IndexBinRow, bool) {
	hasMore := false
	var result []utils.IndexBinRow
	fileName := fileNameBase + ".log"
	f, err := os.Open(fileName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ReverseReadLogFileForIndex error: %s\n", err)
		return result, false
	}
	defer f.Close()

	bufSize := utils.FILE_INFO_BYTE_COUNT * 20
	bs := make([]byte, bufSize)
	offset := utils.FileSize(fileName)
	readSize := 0
	currentCount := 0
	remaining := -1;
	for {
		if offset <= 0 {
			break
		}
		offset = offset - int64(bufSize)
		if offset < 0 {
			remaining = int(offset + int64(bufSize));
			offset = 0
		}
		f.Seek(int64(offset), 0)
		readSize, err = f.Read(bs)
		if err != nil || readSize == 0 {
			break
		}
		if(remaining > 0 && readSize > remaining){
			readSize = remaining;
		}
		var start uint32 = 0
		var temp []utils.IndexBinRow
		for start < uint32(readSize) {
			var row = new(utils.IndexBinRow)
			row.ReadBytes(bs, start)
			//utils.Debug("row.Index: ", row.Index)
			if row.Index == index {
				fname, foundKey := utils.DbGetStringValue(row.FileNameKey, true) // items.get(row.FileNameKey)
				if foundKey {
					row.Name = fname
				}
				temp = append(temp, *row)
			}
			start += utils.FILE_INFO_BYTE_COUNT
		}
		utils.Debugf("readSize:%d, temp.S:%d\n", readSize, len(temp))
		tlen := len(temp)
		if tlen > 0 {

			for i := tlen - 1; i >= 0; i-- {
				if currentCount >= from {
					result = append(result, temp[i])
					if len(result) == maxNumber {
						if i != 0 {
							hasMore = true
						}
						offset = 0
						break
					}
				}
				currentCount++
			}
			temp = temp[:0]
		}
	}
	return result, hasMore
}

func ReadLogFileForIndex(fileNameBase string, index uint32) (*utils.IndexBinRow, bool) {
	fileName := fileNameBase + ".log"
	f, err := os.Open(fileName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ReadLogFileForIndex error: %s\n", err)
		return nil, false
	}
	defer f.Close()

	bufSize := utils.FILE_INFO_BYTE_COUNT * 20
	bs := make([]byte, bufSize)
	readSize := 0
	for {
		readSize, err = f.Read(bs)
		if err != nil || readSize == 0 {
			break
		}
		var start uint32 = 0
		for start < uint32(readSize) {
			var row = new(utils.IndexBinRow)
			row.ReadBytes(bs, start)
			if row.Index == index {
				fname, foundKey := utils.DbGetStringValue(row.FileNameKey, true) // items.get(row.FileNameKey)
				if foundKey {
					row.Name = fname
					return row, true
				}
				//temp = append(temp, *row)
			}
			start += utils.FILE_INFO_BYTE_COUNT
		}
	}
	return nil, false
}

func GetAllSize(hash string) (int64, int64) {
	fileName := utils.GetTopTreeFolder() + utils.HashToPath(hash) + ".bin";
	f, err := os.Open(fileName)
	if err != nil {
		utils.Debugf("GetAllSize, empty directory: %s\n", fileName)
		return 0,0
	}
	defer f.Close()
	var totalSize int64 = 0;
	var fileCount int64 = 0;
	buf := make([]byte, utils.FILE_INFO_BYTE_COUNT*512)
	readSize := 0
	f.Seek(utils.FILE_INFO_BYTE_COUNT,0 )
	for {
		readSize, err = f.Read(buf)
		if err != nil || readSize == 0 {
			break
		}
		var start uint32 = 0 //FILE_INFO_BYTE_COUNT;
		for start < uint32(readSize) {
			var row = new(utils.IndexBinRow)
			row.ReadBytes(buf, start)
			start += utils.FILE_INFO_BYTE_COUNT
			if utils.IsFileModeDeleted(row.FileMode) {
				continue
			}
			if utils.IsFileModeDirectory(row.FileMode) || utils.IsFileModeRepository(row.FileMode) {
				s, c := GetAllSize(row.ToHashString());
				totalSize += s;
				fileCount += c;
			}else {
				totalSize += row.FileSize;
				//utils.Debug("FileHash: ", row.FileNameKey  , "; name: ", row.Name)
				fileCount ++;
			}
		}
	}
	return totalSize,fileCount;
}

func processRowFunc(io *utils.IndexBinRow, args ...interface{}) error {
	if io.Index == 0 {
		if utils.IsFileModeDeleted(io.FileMode) {
			return errors.New("Deleted")
		} else {
			return nil
		}
	}
	fileName, found := utils.DbGetStringValue(io.FileNameKey, true)
	if found {
		io.Name = fileName
	}

	var binItems map[string]*utils.IndexBinRow
	var deletedItemMap map[string]*utils.IndexBinRow
	binItems = args[0].(map[string]*utils.IndexBinRow)
	deletedItemMap = args[1].(map[string]*utils.IndexBinRow)
	if utils.IsFileModeDeleted(io.FileMode) {
		if found {
			deletedItemMap[io.FileNameKey] = io
		}
	} else {
		if found {
			binItems[io.FileNameKey] = io
			//utils.Debugf("Add to binItemMap, file: %s\n", FileName)
		}
	}
	return nil
}

func readIndexBinData(fileName string, binItems map[string]*utils.IndexBinRow, deletedItemMap map[string]*utils.IndexBinRow) {
	ReadBinFileProcessRow(fileName, processRowFunc, binItems, deletedItemMap)
}

func ReadBinFileProcessRow(fileName string, fn func(*utils.IndexBinRow, ...interface{}) error, args ...interface{}) error {
	f, err := os.OpenFile(fileName, os.O_RDONLY, 0) // os.Open(FileName)
	if err != nil {
		//fmt.Fprintf(os.Stderr, "ReadBinFileProcessRow error: %s\n", err)
		return err
	}
	defer f.Close()

	isFirstRow := true

	for {
		buf := make([]byte, utils.FILE_INFO_BYTE_COUNT*512)
		readSize, err := f.Read(buf)
		if err != nil || readSize == 0 {
			break
		}
		var start uint32 = 0 //FILE_INFO_BYTE_COUNT;
		for start < uint32(readSize) {
			var row = new(utils.IndexBinRow)
			row.ReadBytes(buf, start)
			start += utils.FILE_INFO_BYTE_COUNT
			if isFirstRow {
				isFirstRow = false
				continue
			}
			if err = fn(row, args...); err != nil {
				return err
			}
		}
	}
	return err
}

func intToPath(i int) string {
	return fmt.Sprintf("%d/%d/%d/%d/", i%997, i%983, i%991, i)
}

//Only contains the first 3 tokens
func hashToPath3(hash string) string {
	return fmt.Sprintf("%s/%s/%s", hash[0:2], hash[2:4], hash[4:6])
}

func CreateIndex(random string, name string,  repo *utils.Repository) ([]*utils.WriteTask) {
	subPath := utils.HashToPath(utils.NULL_HASH)
	binFile := utils.GetTopTreeFolder() + subPath + ".bin"
	binFileExists := utils.FileExists(binFile)
	if !utils.FileExists(utils.GetTopTreeFolder()) {
		utils.MkdirAll(utils.GetTopTreeFolder())
	}

	var tasks [] *utils.WriteTask;
	index := uint32(2);
	if(!binFileExists) {
		if  utils.TEST {
			random = "123456" //config.Suffix; //GetString("suffix", "123456")
			h := utils.NewHash()
			h.Write([]byte(random))
			random = hex.EncodeToString(h.Sum(nil))

		} else {
			if (random == "") {
				random = utils.GenerateRandomHash()
			}
		}
		task, _ := CreateBinTask(utils.NULL_HASH, utils.NULL_HASH, random, "","")
		tasks = append(tasks, task)

		utils.SetHashSuffix(random)

		utils.Debugf("Suffix:%s\n", utils.GetHashSuffix())

		fileNameKey := utils.CalculateFileNameKey("Shared", true, utils.NULL_HASH, utils.GetHashSuffix());
		task, nameTask := CreateBinTask(utils.SHARED_HASH, utils.SHARED_HASH, utils.NULL_HASH, fileNameKey,"Shared")
		tasks = append(tasks, task)
		tasks = append(tasks, nameTask)

		row := createRowWithHash(1, utils.TYPE_REPOSITORY, fileNameKey, utils.SHARED_HASH)
		r := utils.Repository{};
		attribs := make(map[string][]byte);
		r.Hash = utils.SHARED_HASH;
		r.Name = "Shared"
		r.Local = ""
		attribs[utils.ATTR_REPO] = utils.GetRepositoryInBytes(&r);
		CreateAppendBinRowTask(&tasks, utils.NULL_HASH, utils.NULL_HASH, 1, row, attribs, "", "",  "")
	}else{
		fileSize := utils.FileSize(binFile);
		index = uint32(fileSize/utils.FILE_INFO_BYTE_COUNT);
	}
	utils.Debug("index is ", index);
	repoName := strings.TrimSpace(name)
	top := utils.ROOT_NODE + "/" + repoName
	//func CreateAppendBinRowTask(folderHash string, index uint32, newRowBytes []byte, attribs map[string][]byte) *utils.WriteTask {

	repoHash := utils.GetFolderPathHash(top)
	utils.Debug("top: ", top , "; hash: ", repoHash)
	fileNameKey := utils.CalculateFileNameKey(repoName, true, utils.NULL_HASH, utils.GetHashSuffix());
	row := createRowWithHash(index, utils.TYPE_REPOSITORY, fileNameKey, repoHash)
	attribs := make(map[string][]byte);
	repo.Hash = repoHash;
	attribs[utils.ATTR_REPO] = utils.GetRepositoryInBytes(repo);
	n := repoName;
	if(repo.EncryptionLevel > 0) {
		n = utils.SetDisplayFileName(repoName);
	}
	task, nameTask := CreateBinTask(repoHash, repoHash, utils.NULL_HASH, fileNameKey, n)
	tasks = append(tasks, task)
	tasks = append(tasks, nameTask)
	CreateAppendBinRowTask(&tasks, utils.NULL_HASH, utils.NULL_HASH, index, row, attribs, "", "",  "")

	return  tasks;
}

func PrintChanges(title string, ServerFolderUpdates map[string]*utils.ModifiedFolder) {
	utils.Debugf("\n\n~~~~~~~~~~~~~ %s. ServerFolderUpdates.S: %d\n", title, len(ServerFolderUpdates))
	for _, folder := range ServerFolderUpdates {
		utils.Debugf("serverChange.Local: %s, Offset: %d\n", folder.FolderHash, folder.Offset)
		if len(folder.Rows) == 0 {
			continue
		}
		for k, row := range folder.Rows {
			utils.Debugf("map.k:%d, row.Index:%d; preIndex:%d, NameKey: %s, opMode: %d; conflict: %d", k, row.GetRowIndex(), row.PreviousIndex, row.GetRowFileNameKey(), row.OperationMode, row.Conflict)
		}
	}
	utils.Debug("--------------------------------------------------------")
}
func PrintFolder(title string, folder *utils.ModifiedFolderExt) {
	if folder == nil {
		return
	}
	utils.Debugf("\n\n~~~~~~~~~~~~~ %s. rows.S: %d\n", title, len(folder.Rows))
	if len(folder.Rows) == 0 {
		return
	}
	for k, row := range folder.Rows {
		utils.Debugf("map.k:%d, row.Index:%d; NKey: %s, opMode: %d; conflict: %d, row:%v\n", k, row.GetRowIndex(), row.GetRowFileNameKey(), row.OperationMode, row.Conflict, row.Row)
	}
	utils.Debug("--------------------------------------------------------")
}

func AddRow(this * utils.ModifiedFolderExt, index uint32, mode uint8, arr *[]byte, fileName string, isDir bool, rescan *Rescan) (*utils.ModifiedRow, bool) {
	row := utils.NewModifiedRow(true)
	row.OperationMode = int32(mode)
	if arr != nil {
		row.Row = *arr
	}
	//row.PreviousIndex  = Index;
	row.FileName = fileName
	row.IsDir = isDir
	this.Rows[index] = row
	rescan.changeCount++
	ok := (rescan.changeCount < utils.MAX_CHANGE_COUNT_CLIENT)
	if !ok {
		utils.Debugf("change count exceeds max. current count :%d, max:%d", rescan.changeCount, utils.MAX_CHANGE_COUNT_CLIENT)
		rescan.incomplete = true
	}
	return row, ok
}

func getRealPath(path string) (string, bool) {
	sym, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", false
	}

	absPath, err := filepath.Abs(sym)
	if err != nil {
		return "", false
	}
	return absPath, true
}

func processFileName(fileName string) (string, int, bool) {
	if utils.IsLinux() {
		return fileName, -1, false
	}
	retIndex := -1
	changed := false
	n := len(fileName)
	n1 := n - 1
	b := make([]byte, n)
	index := 0
	var tokens []int
	for i := 0; i < n; i++ {
		if fileName[i] == '[' && i < n1 {
			if fileName[i+1] == '-' { //reserved word
				for j := i + 2; j < n1; j++ {
					if fileName[j] == '-' && fileName[j+1] == ']' {
						changed = true
						sub := fileName[i+2 : j]
						rIndex, err := strconv.Atoi(sub)
						if err == nil {
							retIndex = rIndex
							return fileName[0:i], retIndex, true
						}
					}
				}
			} else if fileName[i+1] == '!' { //CASE problem or invalid chars
				toContinue := false
				for j := i + 3; j < n1; j++ {
					if fileName[j] == '!' && fileName[j+1] == ']' {
						toBreak := false
						sub := fileName[i+2 : j]
						var indexes string
						pos := strings.Index(sub, "_")
						if pos >= 0 {
							indexes = sub[pos+1:]
							sub = sub[0:pos]
						}
						if sub != "" {
							rIndex, err := strconv.Atoi(sub)
							if err == nil {
								retIndex = rIndex
								i = j + 1
								changed = true
								toContinue = true
							}
							toBreak = true
						}
						if indexes != "" {
							ts := strings.Split(indexes, ",")
							valid := true
							for _, token := range ts {
								if !utils.IsInteger(token) {
									valid = false
									break
								}
								tInt, _ := strconv.Atoi(token)
								tokens = append(tokens, tInt)
							}
							if valid {
								toContinue = true
							} else {
								tokens = nil
							}
							toBreak = true
						}

						if toBreak {
							break
						}
					}
				}
				if toContinue {
					continue
				}
			}
		}
		b[index] = fileName[i]
		index++
	}
	n = index //total number of bytes
	if tokens != nil {
		sort.Ints(tokens)
		for _, i := range tokens {
			if i >= n {
				return fileName, -1, false
			}
			if t, ok := utils.ESCAPE_CHARS[b[i]]; ok {
				b[i] = t
			} else {
				return fileName, -1, false
			}
		}
	}
	return string(b[0:n]), retIndex, changed
}

//duplicate file, only diff in case
//return bool changed or not
func fixDuplicateFileName(fileName string, index uint32) (string, bool) {
	if utils.IsLinux() {
		return fileName, false
	}
	dotPos := strings.LastIndex(fileName, ".")
	if dotPos < 0 {
		dotPos = len(fileName)
	}
	return fmt.Sprintf("%s[!%d!]%s", fileName[0:dotPos], index, fileName[dotPos:]), true
}

func fixFileNameForWindows(fileName string, index uint32, getFinalFormat bool) (string, []string, bool) {
	var replaced []string
	var chars []byte
	n := len(fileName)
	lowered := strings.ToLower(fileName)
	if utils.SetContains(utils.WIN_RESERVED_WORDS, lowered) {
		fileName = fmt.Sprintf("%s[-%d-]", fileName, index)
		return fileName, replaced, true
	}
	for i := 0; i < n; i++ {
		c := fileName[i]
		if r, ok := utils.SPECIAL_CHARS[c]; ok {
			if (i > 0 &&  c == ' ') || (i>=0 && c == '.')  {
				//do nothing
			}else {
				replaced = append(replaced, fmt.Sprintf("%d", i))
				c = r
			}
		}
		if i == n-1 && c == '.' {
			replaced = append(replaced, fmt.Sprintf("%d", i))
			c = 'B'
		}
		chars = append(chars, c)
	}
	n = len(replaced)
	if n > 0 {
		fileName = string(chars)
	}
	if getFinalFormat && n > 0 {
		dotPos := strings.LastIndex(fileName, ".")
		if dotPos < 0 {
			dotPos = len(fileName)
		}
		return fmt.Sprintf("%s[!%d_%v!]%s", fileName[0:dotPos], index, strings.Join(replaced, ","), fileName[dotPos:]), replaced, true
	}
	return fileName, replaced, false
}

type DeletedRowData struct {
	index          uint32
	binFilePath    string
	folderHash     string
	newFolderHash  string //the new folder Hash (when it is moved to a new folder)
	notToUpdateRow bool
	row            *utils.ModifiedRow
	fileName string
	fileNameKey string
	hash     string
}

func NewDeletedRowData(index uint32, binFile, folderHash, name string, row *utils.ModifiedRow) *DeletedRowData {
	d := new(DeletedRowData)
	d.index = index
	d.binFilePath = binFile
	d.row = row
	d.folderHash = folderHash
	d.fileName = name
	return d
}

type FolderEx struct{
	repo * utils.Repository;
	hash string;
	hashSuffix string;
	parentHash string;
	relativePath string;
	absPath string;
	files []string;
}
func (f FolderEx)toString() string{
	return f.absPath + "; repo: " + f.repo.Name;
}


type FolderData struct{
	p *ants.PoolWithFunc;
	wg * sync.WaitGroup;
	changedDirs, traversedDirs * syncmap.Map;
	srcAbsPath string;
	files []string;
	currentRelativePath, folderHash, hashSuffix string
	storeFiles bool;
}

func checkChanges(repoHash string, storeFiles bool) * syncmap.Map{
	defer utils.TimeTrack(time.Now(), "checkChanges")
	var wg sync.WaitGroup
	p, _ := ants.NewPoolWithFunc(50, func(i interface{}) {
		doCheckFolder(i)
		wg.Done()
	})
	defer p.Release()



	folders, _,_ := repoToFolderEx()

	traversedDirs := new(syncmap.Map)
	changedDirs := new(syncmap.Map)
	for _, folder := range folders {
		if len(repoHash) > 0{
			if(folder.repo.Hash != repoHash){
				continue
			}
		}
		checkFolder(p, &wg, changedDirs, traversedDirs, folder.absPath, folder.files, folder.relativePath,  folder.repo.Hash, folder.repo.HashSuffix, storeFiles)
	}

	wg.Wait()
	changedDirs = dedup(changedDirs)
	return changedDirs
}
func checkFolder(p *ants.PoolWithFunc, wg * sync.WaitGroup,  changedDirs, traversedDirs * syncmap.Map, srcAbsPath string,
	files []string, currentRelativePath, folderHash, hashSuffix string, storeFiles bool) {
	data := FolderData{
		p:                   p,
		wg:                  wg,
		changedDirs:         changedDirs,
		traversedDirs:       traversedDirs,
		srcAbsPath:          srcAbsPath,
		files:               files,
		currentRelativePath: currentRelativePath,
		folderHash:          folderHash,
		hashSuffix:          hashSuffix,
		storeFiles: storeFiles,
	}
	//WARNING: because it's recursive and thread pool will be used up and got stuck, so when the cap is reached, no new thread will be created.
	if(p.Running() < p.Cap()) {
		wg.Add(1)
		p.Invoke(data)
	}else{
		doCheckFolder(data)
	}

}

func doCheckFolder(i interface{}){
	var changedDirs, traversedDirs * syncmap.Map
	var files []string;
	var  srcAbsPath, currentRelativePath, folderHash, hashSuffix string
	f := i.(FolderData)

	changedDirs = f.changedDirs
	traversedDirs = f.traversedDirs
	files = f.files
	srcAbsPath = f.srcAbsPath
	currentRelativePath = f.currentRelativePath
	folderHash = f.folderHash
	hashSuffix = f.hashSuffix
	storeFiles := f.storeFiles
	srcAbsPath = filepath.Clean(srcAbsPath)

	if traversedDirs != nil {
		traversedDirs.Store(srcAbsPath, true)
	}
	info, _ := os.Lstat(srcAbsPath)
	isDir := info.IsDir();

	config := utils.LoadConfig()
	if isDir && config.HasSelectedFolder() {
		p := currentRelativePath[len(utils.ROOT_NODE) + 1 : ]
		if(config.IsInsideSelectedForlder(p)){
			return;
		}
	}

	if (len(folderHash) == 0) {
		folderHash = utils.GetFolderPathHash(currentRelativePath)
	}

	var fileNames []*utils.RealFileInfo
	if(isDir && len(files) == 0) {
		dir, _ := os.Open(srcAbsPath)
		defer dir.Close()
		fis, _ := dir.Readdir(-1)
		if (len(folderHash) == 0) {
			folderHash = utils.GetFolderPathHash(currentRelativePath)
		}
		for _, fileInfo := range fis {
			fileName := fileInfo.Name()
			if fileName == "." || fileName == ".." || !FilterFile(currentRelativePath+"/"+fileInfo.Name(), fileInfo) {
				continue
			}

			rfi := utils.NewRealFileInfo(fileInfo, filepath.Join(srcAbsPath, fileInfo.Name()))
			if(rfi != nil) {
				fileNames = append(fileNames, rfi)
			}
		}
	}else {

		if (!isDir) {
			if rfi, err := utils.GetRealFileInfo(srcAbsPath); err == nil {
				fileNames = append(fileNames, rfi)
			}

		} else if (len(files) > 0) {
			for _, file := range files {
				if rfi, err := utils.GetRealFileInfo(srcAbsPath + "/" + file); err == nil {
					rfi.IsDir = false;
					rfi.IsFile = true;
					rfi.Name = file;
					fileNames = append(fileNames, rfi)
				}
			}
		}
	}
	checkFolderChanges(f.p, f.wg, changedDirs, traversedDirs, srcAbsPath, currentRelativePath, folderHash, hashSuffix, storeFiles, fileNames)
}

//func (this *Rescan) rescanDirectory(directoryAbsPath string, currentRelativePath string, fileNames []*utils.RealFileInfo, mfolder *utils.ModifiedFolderExt,  updateMeta bool, hashSuffix string) bool {

func  checkFolderChanges(p *ants.PoolWithFunc, wg * sync.WaitGroup, changedDirs, traversedDirs * syncmap.Map,
	srcAbsPath, currentRelativePath, folderHash, hashSuffix string, storeFiles bool, fileNames []*utils.RealFileInfo)bool {
	subPath := utils.HashToPath(folderHash)
	path := utils.GetTopTreeFolder() + subPath
	pathBin := path + ".bin"
	binRowMap := make(map[string]*utils.IndexBinRow) //Map file Name key to IndexBinRow object
	_=ReadBinFileProcessRow(pathBin, func(io *utils.IndexBinRow, args ...interface{}) error {
		if io.Index == 0 {
			if utils.IsFileModeDeleted(io.FileMode) {
				return errors.New("deleted")
			} else {
				return nil
			}
		}
		var binItems map[string]*utils.IndexBinRow
		binItems = args[0].(map[string]*utils.IndexBinRow)
		if !utils.IsFileModeDeleted(io.FileMode) {
			binItems[io.FileNameKey] = io
		}
		return nil
	}, binRowMap)
	skipFile := false
	for _, fileInfo := range fileNames {
		if fileInfo == nil {
			utils.Warn("nil fileinfo. dir:", srcAbsPath)
			continue
		}
		fKey := utils.CalculateFileNameKey(fileInfo.Name, fileInfo.IsDir, folderHash, hashSuffix)
		row, found := binRowMap[fKey]
		if fileInfo.IsDir {
			absPath := filepath.Clean(fileInfo.AbsPath)
			if _, f := traversedDirs.Load(absPath); f {
				continue
			}
			if(!found){
				//new folder
				if(storeFiles){
					changedDirs.Store(filepath.Join(srcAbsPath , fileInfo.Name), false)
				}else {
					changedDirs.Store(srcAbsPath, true)
				}
			}else {
				checkFolder(p, wg, changedDirs, traversedDirs, absPath, nil,
					currentRelativePath+"/"+fileInfo.Name, "", hashSuffix, storeFiles)
			}
		}else {
			if (skipFile) {
				continue
			}
			if  found {
				changed := false;
				if  row.FileSize == fileInfo.Size && row.LastModified != fileInfo.LastModified {
					h := utils.GetFileHash(filepath.Join(srcAbsPath , fileInfo.Name), hashSuffix)
					if h != row.ToHashString() {
						changed = true;
					}
				}

				if  changed || row.FileSize != fileInfo.Size {
					if _, f := changedDirs.Load(srcAbsPath); !f {
						if(storeFiles){

							changedDirs.Store(filepath.Join(srcAbsPath , fileInfo.Name), false)
						}else {
							changedDirs.Store(srcAbsPath, false)
						}
						skipFile = true
					}
					continue
				}
			} else {
				if _, f := changedDirs.Load(srcAbsPath); !f {
					if(storeFiles){
						changedDirs.Store(filepath.Join(srcAbsPath , fileInfo.Name), false)
					}else {
						changedDirs.Store(srcAbsPath, false)
					}

					skipFile = true
				}
				continue
			}
		}
	}
	return false
}

func dedup(folders  * syncmap.Map)  * syncmap.Map{
	var deletes []string
	folders.Range(func(k, v interface{}) bool {
		folder := k.(string)
		orig := folder
		for{
			parent := filepath.Dir(folder)
			if(parent == folder){
				break;
			}
			if v, f := folders.Load(parent) ; f{
				if(v.(bool)) {//the parent directory is recursive scan
					deletes = append(deletes, orig)
					break;
				}
			}
			folder = parent;
		}

		return true
	})

	for _, d := range deletes{
		folders.Delete(d)
	}
	return folders
}
