// Copyright (c) 2020, Yanbin (Henry) Zheng <ybzheng@gmail.com>
// All rights reserved.
//
// Use of this source code is governed by a AGPLv3 license that can be
// found in the LICENSE file.
package client

import (
	"fmt"
	"golang.org/x/sync/syncmap"
	"os"
	"strconv"
	"strings"
	utils "github.com/anysync/server/utils"
)

func addFileToPacksFolder(repository *utils.Repository, folderHash, fileHash, fileNameKey string, fileSize int64, filePath string, objects *syncmap.Map,  deletes *syncmap.Map) {
	count := 0
	packFolder := utils.GetPacksFolder() + repository.Name + "/"
	if !utils.FileExists(packFolder) {
		utils.Mkdir(packFolder)
	}
	countFile := packFolder + "count"
	if text, err := utils.ReadString(countFile); err == nil {
		count, _ = strconv.Atoi(text)
	}
	utils.Debug("Enter addFile, folder:", folderHash, "; file: ", fileHash, ", fKey: ", fileNameKey, "; size: ", fileSize, "; count: ", count)
	count += int(fileSize)
	fileName := fmt.Sprintf("%s%s.%s.pki", packFolder, folderHash, fileNameKey)
	text := fmt.Sprintf("%s.%d", fileHash, fileSize)
	utils.Debug("Write to pack folder ", fileName, "; content: ", text)
	utils.WriteString(fileName, text)
	utils.CopyFile(filePath, fileName + utils.EXT_OBJ)
	utils.WriteString(countFile, fmt.Sprintf("%d", count))
	utils.Debug("PackMinSize: ", utils.LoadConfig().PackMinSize)
	if count >= utils.LoadConfig().PackMinSize /* PACK_FILE_SIZE_MAX_THRESHOLD*/ {
		generatePackFile(repository, objects,   deletes)
		utils.RemoveAllFiles(packFolder)
		//utils.Mkdir(utils.GetPacksFolder());
	}
}

func generatePackFile(repository *utils.Repository, objects *syncmap.Map,  deletes * syncmap.Map) {
	packFolder := utils.GetPacksFolder() + repository.Name + "/"

	dir, err := os.Open(packFolder)
	if err != nil {
		return
	}
	defer dir.Close()
	fis, err := dir.Readdir(-1) //fis is already sorted by file RemoteName
	if err != nil {             //may be because there is no privilege
		return
	}
	tmpPackFileName := packFolder + "pack"
	var fileParts []*utils.FileMeta
	var packSize int64
	for _, fileInfo := range fis {
		name := fileInfo.Name()
		if !strings.HasSuffix(name, ".pki") {
			continue
		}
		fileName := packFolder + name
		text, _ := utils.ReadString(fileName)
		tokens := strings.Split(text, ".")
		fileHash := tokens[0]
		//fileSize := tokens[1]
		//size, _ := strconv.Atoi(fileSize)
		if filePart, ps := appendToPackFile(tmpPackFileName, fileName+utils.EXT_OBJ,  fileHash, repository.EncryptionLevel > 0); filePart != nil {
			fileParts = append(fileParts, filePart)
			packSize += ps
		}
	}
	utils.Debug("To generate final pack, packSize:", packSize, "; fileparts.count: ", len(fileParts))
	generateFinalPackFile(repository,  fileParts, objects,   deletes)
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
...
*/
func appendToPackFile(packObjPath string, smallFilePath string,  fileHash string, isEncrypted bool) (*utils.FileMeta, int64) {
	fsize := utils.FileSize(packObjPath)
	from := fsize
	var headers []byte
	if fsize == 0 {
		headers = []byte("PACK0001")
	}

	var smallFileSize int64
	if( isEncrypted) {
		tmpFile := utils.GetTopTmpFolder() + utils.GenerateRandomHash();
		var err error;
		if err = utils.CompressLz4(smallFilePath, tmpFile); err == nil {
			var key [32]byte;
			if key, err = utils.GetFileEncKey(fileHash); err == nil {
				tmpFile2 := utils.GetTopTmpFolder() + utils.GenerateRandomHash();
				if err = utils.EncryptFile( tmpFile, tmpFile2, &key); err == nil {
					utils.RemoveFile(tmpFile);
					smallFilePath = tmpFile2;
				}
			}
		}
		if(err != nil){
			utils.Warn("Encryption error: ", err)
			return nil, 0;
		}
	}
	smallFileSize = utils.FileSize(smallFilePath);

	headers = append(headers, utils.FromHex(fileHash)...)
	lenBytes := make([]byte, 4)
	utils.PutUint32(lenBytes, 0, uint32(smallFileSize))
	headers = append(headers, lenBytes...)
	utils.AppendBytes(packObjPath, headers)
	headerLen := int64(len(headers))
	from += headerLen
	utils.AppendFile(packObjPath, smallFilePath)

	if(isEncrypted){
		utils.RemoveFile(smallFilePath)//remove the tmp file
	}

	return utils.NewFileMeta(utils.FILE_META_TYPE_REGULAR, "", from, smallFileSize, fileHash), smallFileSize + headerLen
}

func generateFinalPackFile(repository * utils.Repository,  fileParts []*utils.FileMeta, objects *syncmap.Map,
	 deletes * syncmap.Map) {
	lastModified := uint32(0)
	var fileHash string;
	fileParts, filePart, err := CompressAndUploadPack( fileParts, deletes, repository, objects);
	fileHash = filePart.GetFileHash()
	if  err != nil {
		utils.Error("Error occurred in CloudCopy: ", err)
	}else {
		for _, part := range fileParts {
			if lastModified == 0 {
				lastModified = part.GetLastModified()
			}
			part.P = fileHash
			part.T = utils.FILE_META_TYPE_PACK_ITEM
			objects.Store(part.GetFileHash(), part) // currentRemote + ":" + "anysync/objects/" + fullHashPath ;
		}

		filePart.SetLastModified(lastModified) //use the first part's lastModified value.
		if filePart.GetIncomplete() == 0 {
			objects.Store(fileHash, filePart)
		}
	}
}
