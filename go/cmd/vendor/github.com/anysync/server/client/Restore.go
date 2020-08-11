// Copyright (c) 2020, Yanbin (Henry) Zheng <ybzheng@gmail.com>
// All rights reserved.
//
// Use of this source code is governed by a AGPLv3 license that can be
// found in the LICENSE file.
package client

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
	utils "github.com/anysync/server/utils"
)

func processRow(io *utils.IndexBinRow, args ...interface{}) error {
	if io.Index == 0 || utils.IsFileModeDeleted(io.FileMode) {
		return nil
	}
	var err error
	sha := io.ToHashString()
	//utils.Debug("Process row. objHash:", sha)
	fileNameKey := io.FileNameKey
	relativePath := args[0].(string)
	fileName, foundKey := utils.DbGetStringValue(fileNameKey, true) // items.get(FileNameKey);
	//fmt.Printf("relPath:%s, FileNameKey:%s, val:%s\n", relativePath, FileNameKey, fileName)
	if !foundKey {
		return nil
	}
	var restoreRootDir string
	restoreRootDir = args[1].(string) //Type assertion. https://tour.golang.org/methods/15
	folderHash := args[2].(string)
	repoName := args[3].(string)
	hashSuffix := args[4].(string)
	dest := restoreRootDir + "/" + relativePath + "/" + fileName
	//utils.Debug("destFile:", dest)
	utils.SendMsg( "To restore file " + dest)
	fName, t, _ := GetFileNameModTimeAndSize(dest)
	if t > 0 && fName != fileName {
		fileName, _ = fixDuplicateFileName(fileName, io.Index)
		dest = restoreRootDir + "/" + relativePath + "/" + fileName
	}
	if utils.IsFileModeDirectory(io.FileMode) {
		if !utils.FileExists(dest) {
			utils.MkdirAll(dest)
		}
		traverseTree(restoreRootDir, sha, relativePath+"/"+fileName, repoName, hashSuffix)
	} else if utils.IsFileModePipe(io.FileMode) {
		if !utils.IsWindows() {
			MkFifo(dest)
			if !utils.FileExists(dest) {
				return nil
			}
			utils.UpdateFileMetaData(dest, io.CreateTime, io.LastModified, io.FileMode, folderHash, io.Index)
		}
	} else { //it's file or pipe
		dir := filepath.Dir(dest)
		if !utils.FileExists(dir) {
			utils.MkdirAll(dir)
		}
		path := utils.HashToPath(sha)
		toDownload := true
		fileInfo := utils.GetTopObjectsFolder() + path + utils.EXT_OBJ
		//fmt.Printf("fileInfo:%s; dest:%s\n", fileInfo, dest);
		var fileHash string
		if utils.FileExists(dest) {
			fileHash = utils.GetFileHash(dest, hashSuffix)
			//utils.Debug("fileHash: ", fileHash, "; io.bin.hash: ", sha)
		}
		if sha == fileHash {
			//utils.Debug("Skip download:", dest)
			toDownload = false
		} else if utils.FileExists(fileInfo) {
			meta := utils.GetDatObject(sha)
			//datFileName := utils.GetTopObjectsFolder() + path + utils.EXT_DAT
			if meta == nil {
				utils.Debug(".dat file does not exist: ", sha)
				if io.FileSize == 0 {
					utils.CreateZeroLengthFile(dest)
					toDownload = false
				} else {
					return errors.New("no dat file: " + sha)
				}
			} else {

				if err := decryptAndRestoreTo(meta, sha, dest); err == nil {
					toDownload = false
				}
			}
		} else if io.FileSize == 0 || sha == utils.ZERO_HASH {
			utils.CreateZeroLengthFile(fileInfo)
			utils.CreateZeroLengthFile(dest)
			toDownload = false
		}

		if toDownload {
			//utils.Debug("To download:", dest)
			for i := 0; i < 3; i++ {
				utils.Debug("Before calling GetCloudFile, sha:", sha, "; filehash:", fileHash)
				//fmt.Println("GetCloudFile:", sha, "to", dest)
				if err = GetCloudFile(fileInfo, sha, dest); err != nil {
					utils.Errorf("Couldn't download file : %s", fileInfo)
				} else {
					break
				}
				time.Sleep(time.Second * 10)
			}
			if err != nil {
				return err
			}
		}
		if !utils.FileExists(dest) {
			return nil
		}
		utils.UpdateFileMetaData(dest, io.CreateTime, io.LastModified, io.FileMode, folderHash, io.Index)
	}

	return nil
}

func traverseTree(restoreRootDir string, hash string, originalPath string, repoName, hashSuffix string) error {
	path := utils.HashToPath(hash)
	binFile := utils.GetTopTreeFolder() + path + ".bin"
	var restoreDir string
	if utils.FileExists(binFile) {
		if len(restoreRootDir) == 0 {
			restoreDir = utils.GetTopRestoreFolder() + originalPath
		} else {
			restoreDir = restoreRootDir + "/" + originalPath
		}
		if !utils.FileExists(restoreDir) {
			utils.MkdirAll(restoreDir)
		}
		if err := ReadBinFileProcessRow(utils.GetTopTreeFolder()+"/"+path+".bin", processRow, originalPath, restoreRootDir, hash, repoName, hashSuffix); err != nil {
			return err
		}
	}
	return nil
}

func Restore(restoreRootDir string) error {
	reposMap := utils.GetRepositoryMap()
	for _, repo := range reposMap {
		hash := repo.Hash
		name := repo.Name
		if err := traverseTree(restoreRootDir, hash, name, name, repo.HashSuffix); err != nil {
			return err
		}
	}
	return nil
}

//Delete local dirs and restore them from data under tree/objects directory.
func RestoreToConfiguredPlace(repo *utils.Repository) error {
	//fmt.Printf("Name: %s, Hash:%s\n", repo.Name, repo.Hash)
	dir := repo.Local
	hash := repo.Hash
	name := repo.Name
	if !utils.FileExists(dir) {
		utils.MkdirAll(dir)
	}
	//the following was modified version of traverseTree() func
	path := utils.HashToPath(hash)
	binFile := utils.GetTopTreeFolder() + path + ".bin"
	var restoreDir string
	if utils.FileExists(binFile) {
		restoreDir = dir
		if !utils.FileExists(restoreDir) {
			utils.MkdirAll(restoreDir)
		}
		if err := ReadBinFileProcessRow(utils.GetTopTreeFolder()+"/"+path+".bin", processRow, "", restoreDir, hash, name, repo.HashSuffix); err != nil {
			return err
		}
	}
	return nil
}

func processRow2(io *utils.IndexBinRow, args ...interface{}) string {
	if io.Index == 0 || utils.IsFileModeDeleted(io.FileMode) {
		return ""
	}
	hash := io.ToHashString()
	fileMeta := utils.GetDatObject(hash) // utils.StringToFileMeta(text);
	if fileMeta == nil {
		return ""
	}
	pos := strings.Index(fileMeta.P, ":")
	if pos < 0 {
		return ""
	}
	text := fileMeta.P[pos+1:]
	pos = strings.Index(text, "/objects")
	if pos < 0 {
		return ""
	}
	return text[0:pos]
}

func ReadBinFileProcessRow2(fileName string) string {
	f, err := os.OpenFile(fileName, os.O_RDONLY, 0) // os.Open(FileName)
	if err != nil {
		//fmt.Fprintf(os.Stderr, "ReadBinFileProcessRow error: %s\n", err)
		return ""
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

			path := processRow2(row)
			if len(path) > 0 {
				return path
			}
			if utils.IsFileModeDirectory(row.FileMode) {
				path = traverseTreeGetTopCloudPath(row.ToHashString())
				if len(path) > 0 {
					return path
				}
			}
		}
	}
	return ""
}

func traverseTreeGetTopCloudPath(hash string) string {
	path := utils.HashToPath(hash)
	binFile := utils.GetTopTreeFolder() + path + ".bin"
	if utils.FileExists(binFile) {
		//utils.Debug("To process binfile:", binFile)
		path := ReadBinFileProcessRow2(utils.GetTopTreeFolder() + "/" + path + ".bin")
		return path
	}
	return ""
}

func GetUserCloudTopPath() string {
	var ret string;
	utils.IterateDatObject(func(key []byte, fileMeta *utils.FileMeta)bool {
		if fileMeta == nil {
			return true;
		}
		pos := strings.Index(fileMeta.P, ":")
		if pos < 0 {
			return true;
		}
		text := fileMeta.P[pos+1:]
		pos = strings.Index(text, "/objects")
		if pos < 0 {
			return true;
		}
		ret = text[0:pos]
		return false;//stop iterating
	})
	return ret;
}

//Rename non-current version .dat files to .dtt, so that download only current version
//It calls ObjectsDbSetStateValuesTo(0) to set values to 0, then set to 1 for all current files.
func CleanDatFiles() {
	utils.TimeTrack(time.Now(), "CleanDatFiles")
	utils.ObjectsDbSetStateValuesTo(0)
	reposMap := utils.GetRepositoryMap()
	for _, repo := range reposMap {
		hash := repo.Hash
		if hash == utils.SHARED_HASH {
			continue
		}
		path := CleanDatFilesTraverseTree(hash)
		if len(path) == 0 {
			continue
		} else {
			return
		}
	}
}

func CleanDatFilesTraverseTree(hash string) string {
	path := utils.HashToPath(hash)
	binFile := utils.GetTopTreeFolder() + path + ".bin"
	if utils.FileExists(binFile) {
		//utils.Debug("To process binfile:", binFile)
		path := CleanDatFilesProcessRow(utils.GetTopTreeFolder() + "/" + path + ".bin")
		return path
	}
	return ""
}

func CleanDatFilesProcessRow(fileName string) string {
	f, err := os.OpenFile(fileName, os.O_RDONLY, 0) // os.Open(FileName)
	if err != nil {
		//fmt.Fprintf(os.Stderr, "ReadBinFileProcessRow error: %s\n", err)
		return ""
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

			CleanDatFilesProcessIndexRow(row)
			if utils.IsFileModeDirectory(row.FileMode) {
				path := CleanDatFilesTraverseTree(row.ToHashString())
				if len(path) > 0 {
					return path
				}
			}
		}
	}
	return ""
}

func CleanDatFilesProcessIndexRow(io *utils.IndexBinRow) {
	if io.Index == 0 || utils.IsFileModeDeleted(io.FileMode) {
		return
	}
	hash := io.ToHashString()
	CleanDatFilesProcessDatFile(hash)
}
func CleanDatFilesProcessDatFile(hash string) {
	var meta *utils.FileMeta
	var changed bool
	if meta, changed = utils.ObjectsDbSetStateValueTo(hash, 1); !changed {
		return
	}

	var hashes string
	if meta.T == utils.FILE_META_TYPE_CHUNKS {
		hashes = meta.P
	} else if meta.T == utils.FILE_META_TYPE_PACK {
		hashes = meta.B
	} else if meta.T == utils.FILE_META_TYPE_PACK_ITEM {
		CleanDatFilesProcessDatFile(meta.P)
		return
	} else {
		return
	}
	hashArr := GetChunksHash(hashes)
	for _, h := range hashArr {
		CleanDatFilesProcessDatFile(h)
	}
}

func UpdateBinFilesUntil(t int64) {
	utils.RenameRecursively(utils.GetTopTreeFolder(), utils.EXT_BIN, ".bii")
	readLogUntil(utils.GetAppHome()+"server.bin", t)
}

func readLogUntil(serverBinFileName string, endTime int64) bool {
	fmt.Println("Enter readLogSince. BinFileName:", serverBinFileName, "; endTime:", endTime, "; endTime.unix:", endTime)
	if !utils.FileExists(serverBinFileName) {
		fmt.Println("bin file does not exist:", serverBinFileName)
		return true
	}
	file, err := os.Open(serverBinFileName)
	if err != nil {
		fmt.Println("readLogUntil returns false 1")
		return false
	}
	defer file.Close()
	fileSize := utils.FileSize(serverBinFileName)
	rowCount := int(fileSize / utils.SERVER_LOG_BIN_ROW_SIZE)
	fmt.Println("RowCount:", rowCount)
	if rowCount == 0 {
		return true
	}
	rowIndex := 0
	readCount := 0
	for {
		buf := make([]byte, utils.SERVER_LOG_BIN_ROW_SIZE*512)
		readCount, err = file.Read(buf)
		if err != nil || readCount == 0 {
			fmt.Println("Read error:", err)
			break
		}
		fmt.Println("readCount:", readCount)
		toExit := false
		start := 0
		for start < readCount {
			var s = buf[start : start+4]
			begin := binary.BigEndian.Uint32(s) //id
			start += 4

			s = buf[start : start+4]
			timestamp := binary.BigEndian.Uint32(s) //Timestamp
			fmt.Println("timestamp:", timestamp, "; time:", time.Unix(int64(timestamp), 0))
			if timestamp > uint32(endTime) {
				toExit = true
				break
			}
			start += 4

			s = buf[start : start+4]
			end := binary.BigEndian.Uint32(s)
			start += 4

			hash := buf[start : start+utils.HASH_BYTE_COUNT]
			sha := fmt.Sprintf("%x", hash)
			fmt.Println("to call handleRows, hash:", sha)
			handleRows(sha, int(begin), int(end))
			rowIndex++
			start += utils.HASH_BYTE_COUNT
			if rowIndex >= rowCount {
				toExit = true
				break
			}
		}
		if toExit {
			break
		}
	}
	fmt.Println("Return from readLogUntil")
	return true
}

func handleRows(hash string, begin, end int) {
	fmt.Println("Enter handleRows, hash:", hash, "; begin:", begin, "; end:", end)
	fileName := utils.GetTopTreeFolder() + utils.HashToPath(hash) + utils.EXT_LOG
	binFileName := utils.GetTopTreeFolder() + utils.HashToPath(hash) + utils.EXT_BIN
	file, err := os.Open(fileName)
	if err != nil {
		fmt.Printf("loadRowsFromLogFile. File:%s. Cannot open file: %s\n", fileName, err)
		return
	}
	defer file.Close()
	if begin > 0 {
		file.Seek(int64(begin), 0)
	}
	var index uint32 = 0
	readCount := 0
	count := 0
	for {
		buf := make([]byte, utils.FILE_INFO_BYTE_COUNT*512)
		readCount, err = file.Read(buf)
		fmt.Println("In loadRows, readCount:", readCount)
		if err != nil || readCount == 0 {
			break
		}
		start := 0
		fmt.Println("start: ", start, "; readCount: ", readCount)
		for start < readCount && (begin+count+utils.FILE_INFO_BYTE_COUNT) <= end {
			var s = buf[start : start+utils.FILE_INFO_BYTE_COUNT]
			var row = utils.NewModifiedRow(false)
			row.Row = s

			start += utils.FILE_INFO_BYTE_COUNT
			count += utils.FILE_INFO_BYTE_COUNT

			io := row.GetIndexBinRow()
			index = io.Index
			fileSize := utils.FileSize(binFileName)
			binRows := uint32(fileSize / utils.FILE_INFO_BYTE_COUNT)
			fmt.Println("here, start:", start, "; row.len:", len(row.Row), "; index:", io.Index, "; fileSize:", fileSize, "; rows:", binRows)
			if io.Index < binRows {
				pos := index * utils.FILE_INFO_BYTE_COUNT
				f, _ := os.OpenFile(binFileName, os.O_RDWR, utils.NEW_FILE_PERM)
				f.Seek(int64(pos), 0)
				n, err := f.Write(row.Row)
				fmt.Println("index:", index, ". Write one row to:", binFileName, "; writeCount:", n, "; error:", err)
				f.Close()
			} else {
				fmt.Println("To append bytes to", binFileName)
				utils.AppendBytes(binFileName, row.Row)
			}
		}
	}

}

func RestoreToLocal(restoreDirectory string, until int64, mode int, exit bool) {
	utils.ResetCallback = func() {
		//Invoked after resetgetall downloaded and created tree and objects directories.\
		fmt.Println("Meta data downloaded.")
		config := utils.LoadConfig()
		config.Mode = mode
		SaveConfig()
		if mode == utils.CONFIG_MODE_PLACEHOLDER {
			if exit {
				os.Exit(0)
			}
			return
		}
		if until > 0 {
			UpdateBinFilesUntil(until)
		}
		paths := url.Values{}
		paths.Set("local0", restoreDirectory)
		RestoreAll(paths)

		fmt.Println("Complete successfully.")
		if exit {
			os.Exit(0)
		}
	}
	utils.Listener(true, "", nil);
}

func toRestore(r *http.Request) {
	u, _ := url.Parse(r.RequestURI)
	utils.Debug("Request: ", u.RequestURI())
	mode := u.Query().Get("mode")
	if mode == "p" { //placeholder mode
		config := utils.LoadConfig()
		config.Mode = utils.CONFIG_MODE_PLACEHOLDER
		SaveConfig()
	} else {
		RestoreAll(u.Query())
		//ToRestoreToLocal(u.Query())
	}
}

func ToRestoreToLocal(paths url.Values) {
	list := utils.GetRepositoryList()
	config := utils.LoadConfig()
	config.Mode = utils.CONFIG_MODE_BIDIRECTION
	i := 0
	for _, repo := range list {
		if repo.Hash == utils.SHARED_HASH {
			continue
		}
		k := fmt.Sprintf("local%d", i)
		path := paths.Get(k)
		utils.Debug("i=", i, "; path is ", path)
		//path := u.Query().Get(k);
		path, _ = url.QueryUnescape(path)
		utils.Debug("P is ", path)
		if len(path) == 0 {
			continue
		}
		repo.Local = path
		config.Locals += fmt.Sprintf("%d%s%s", repo.Index, utils.LOCALS_SEPARATOR2, path)
		utils.UpdateRepository(repo)
		RestoreToConfiguredPlace(repo)
		i++
	}
	SaveConfig()
	shares := utils.GetShareFolderList(list)
	for _, shareFolder := range shares {
		localBinFile := utils.GetTopTreeFolder() + utils.HashToPath(shareFolder.Hash) + utils.EXT_BIN
		utils.Debug("Copy bin to ", localBinFile)
		UpdateLocalShareFolder(shareFolder.Hash, localBinFile, shareFolder.Includes)
	}

	utils.SendToLocal("restoreDone")
	utils.SendToLocal("reloadTree")
}

func RestoreAll(paths url.Values) {
	SyncState = SYNC_STATE_RESTORING
	CleanDatFiles()

	/*
	path := GetUserCloudTopPath()   // "AnySync1/5f03be5c599df0d0089e9292d9efa7ec21cd7741c22d0f20dd63603c"
	path = utils.LoadAppParams().GetSelectedStorage().RemoteNameCode + ":" + path + "/objects" //   "1:AnySync1/5f03be5c599df0d0089e9292d9efa7ec21cd7741c22d0f20dd63603c/objects"
	args := []string{path, utils.GetAppHome()}
	fsrc, fdst := cmd.NewFsSrcDst(args)
	utils.Debug("RestoreAll. To call CopyDir")
	fsync.CopyDir(context.Background(), fdst, fsrc, true)
	*/
	utils.Debug("CopyDir returned. To restore to local:", paths)
	ToRestoreToLocal(paths)
	utils.SendToLocal(utils.MSG_PREFIX + "Finished restoring files.")
	utils.Debug("Restore to local done")
	utils.ObjectsDbSetStateValuesTo(1)
	SyncState = SYNC_STATE_SYNCED

	//utils.RenameRecursively(utils.GetTopObjectsFolder(), utils.EXT_DTT, utils.EXT_DAT);
}
