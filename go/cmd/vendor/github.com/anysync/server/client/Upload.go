// Copyright (c) 2020, Yanbin (Henry) Zheng <ybzheng@gmail.com>
// All rights reserved.
//
// Use of this source code is governed by a AGPLv3 license that can be
// found in the LICENSE file.
package client

import (
	"fmt"
	"github.com/disintegration/imaging"
	"github.com/h2non/filetype"
	"golang.org/x/sync/syncmap"
	"io/ioutil"
	"path/filepath"
	"strings"
	"time"
	utils "github.com/anysync/server/utils"
)


func (rescan Rescan) uploadToCloud(repo * utils.Repository, clientChanges []*utils.ModifiedFolderExt, objects *syncmap.Map,  deletes  *syncmap.Map, shareState int32)error {
	packFolder := utils.GetTopTmpFolder() + "/pack/" + repo.Name + "/"
	if utils.FileExists(packFolder) {
		utils.Mkdir(packFolder)
	}
	var packSize int64 = 0
	var fileParts []* utils.FileMeta
	for _, folder := range clientChanges {
		hasImage := false;
		for _, row := range folder.GetRows() {
			var indexBinRow utils.IndexBinRow
			indexBinRow.ReadBytes(row.Row, 0)
			objFilePath := utils.GetTopObjectsFolder() + utils.HashToPath(indexBinRow.ToHashString()) + utils.EXT_OBJ
			if IsImageFile(objFilePath, false) {
				hasImage = true;
			}
			pSize, filePart := uploadProcessFile(&indexBinRow, folder, objects, deletes)
			if pSize > 0 {
				packSize += pSize
			}
			if filePart != nil {
				filePart.SetFolderHash(folder.FolderHash)
				filePart.SetRelativePath( folder.RelativePath)
				filePart.SetFileNameKey(row.GetRowFileNameKey())
				fileParts = append(fileParts, filePart)
			}
			if packSize >= utils.PACK_FILE_SIZE_MAX_THRESHOLD {
				utils.Debugf("### Over pack size threshold. packsize: %d, parts.size:%d", packSize, len(fileParts))
				generateFinalPackFile(repo, fileParts, objects,  deletes)
				fileParts = nil
				packSize = 0
			}

		}
		if hasImage && createThumbnailsForFolder(folder.FolderHash, folder, repo.EncryptionLevel == 1) {
			if fp, e := uploadThumbnail(repo, folder.FolderHash, deletes ); e == nil {
				objects.Store(folder.FolderHash, fp)
			}
			folder.HasThumbnail = true;
		}
	}
	if packSize > 0 {
		n := len(fileParts)
		config := utils.LoadConfig();
		if (n > 2 && packSize > int64(config.PackMinSize) ) || n >= utils.PACK_FILE_MIN_FILE_COUNT {
			utils.Debug("### Leftover pack size:", packSize, "; number of files: ", n)
			generateFinalPackFile(repo,  fileParts, objects,    deletes)
		} else {
			utils.Debugf("No need to create pack file, packSize:%d, parts.size:%d\n", packSize, len(fileParts))
			for _, filePart := range fileParts {
				var shareFolderKey []byte;
				var owner string;
				if(shareState == utils.REPO_SHARE_STATE_SHARE || shareState == utils.REPO_SHARE_STATE_OWNER){
					share := utils.GetShareFolderByRepoHash(utils.GetTopTreeFolder(), filePart.GetFolderHash())
					if share != nil && share.EncryptionLevel > 0 {
						shareFolderKey = share.GetShareFolderKey()
						if(shareState == utils.REPO_SHARE_STATE_SHARE){
							owner = share.Owner;
						}
					}
				}
				jPart := utils.NewFileMeta(utils.FILE_META_TYPE_REGULAR, "", 0, filePart.S, filePart.GetFileHash())
				filePath := utils.GetTopObjectsFolder() + utils.HashToPath(jPart.GetFileHash()) + utils.EXT_OBJ
				setFileMeta(jPart, "", repo, filePart.GetLastModified())
				if(shareFolderKey != nil) {
					setFileMetaKey(shareFolderKey, jPart, filePart.GetFileHash(), filePart.GetFolderHash())
				}
				if err := CompressAndUpload(filePath, jPart, deletes, false, false, owner, objects); err != nil {
					utils.Error("Error occurred in CloudCopy: ", err)
					if jPart.GetIncomplete() == 2 { //nothing uploaded
						continue
					}
				}else {
					addFileToPacksFolder(repo, filePart.GetFolderHash(), filePart.GetFileHash(), filePart.GetFileNameKey(), filePart.S, filePath, objects,  deletes)
				}
			}
		}
	}

	return  nil // everything ok, send nil, error if not
}

func uploadProcessFile(row *utils.IndexBinRow, folder *utils.ModifiedFolderExt, objects *syncmap.Map, deletes *syncmap.Map) (int64, *utils.FileMeta) {
	opMode := row.OperationMode
	var ret int64
	var fileHash string
	var filePart *utils.FileMeta
	ret = 0
	if opMode != utils.MODE_NEW_FILE && opMode != utils.MODE_MODIFIED_CONTENTS && opMode != utils.MODE_REINSTATE_FILE {
		return 0, nil
	}

	//var indexBinRow utils.IndexBinRow
	//indexBinRow.ReadBytes(row.Row, 0)
	fileHash = row.ToHashString()
	//utils.Debugf("BinFileName:%s, Index:%d, FileHash:%s\n", BinFileName, Index, FileHash);
	hPath := utils.HashToPath(fileHash)
	fullHashPath := hPath + utils.EXT_OBJ
	base := utils.GetTopObjectsFolder() + hPath
	objFilePath := utils.GetTopObjectsFolder() + fullHashPath
	if !utils.FileExists(objFilePath) {
		return ret, filePart
	}else{
		deletes.Store(filepath.Dir(objFilePath), true);
	}

	//var jsonText string
	s := row.FileSize
	meta, _ := utils.GetDatObjectAndContent(fileHash)
	if meta != nil {// utils.FileExists(datFile) {
		utils.Debugf("datFile already exists: %s\n", fileHash)
		meta.SetFileHash( fileHash );
		objects.Store(fileHash, meta)
	} else {
		//Now it's time to create object's meta file (*.dat)
		small := (s < utils.SMALL_FILE_SIZE_THRESHOLD && s > 0)
		huge := s >= utils.CHUNKING_FILE_SIZE_THRESHOLD
		//xdiffable := isXDiffApplicable(s)
		if small {
			filePart = utils.NewFileMeta(utils.FILE_META_TYPE_REGULAR, objFilePath, 0, s, fileHash)
			ret = s;
			//filePart, ret =  appendToPackFile(packObjPath, objFilePath, s, fileHash)
			filePart.SetLastModified( row.LastModified)
		} else if huge { //needs chunking
			//oldBinRow := GetRowAt(BinFileName, Index);
			utils.SendToLocal(utils.MSG_PREFIX + "To split file: " + base)
			utils.Debugf("Huge file, to call split, base:%s\n", base)
			SplitAndUpload(folder.Repository, base, objects,  deletes, fileHash)
		} else { //normal
			//var deltaHash, oldHash string
			mType := utils.FILE_META_TYPE_REGULAR
			//if xdiffable {
			//	oldBinRow := utils.GetRowAt(binFileName, index)
			//	if oldBinRow != nil && isXDiffApplicable(oldBinRow.FileSize) {
			//		oldHash = oldBinRow.ToHashString()
			//		oldHash = getOriginalBase(oldHash)
			//		isDeltaSmall, deltaFileName, dsize := diff(objFilePath, s, oldHash)
			//		utils.Debugf("isSmallDelta:%v, deltaSize:%d, file:%s\n", isDeltaSmall, dsize, deltaFileName)
			//		if isDeltaSmall {
			//			deltaHash = utils.GetFileHash( deltaFileName, hashSuffix)
			//			filePart = utils.NewFileMeta(utils.FILE_META_TYPE_REGULAR, "", 0, dsize, deltaHash) //createJsonTextForType(deltaHash, dsize, utils.FILE_META_TYPE_REGULAR);
			//			deltaFileObjName := utils.GetTopObjectsFolder() + utils.HashToPath(deltaHash) + utils.EXT_OBJ
			//			utils.Rename(deltaFileName, deltaFileObjName)
			//			utils.Debugf("DeltaHash:%s\n", deltaHash)
			//			filePart.SetFileHash( deltaHash )
			//			setFileMeta(filePart, "", folder.Repository, indexBinRow.LastModified)
			//			//if err := CloudCopyLz4File(deltaFileObjName, filePart.P, encrypt); err != nil {
			//			if err := CompressAndUpload(deltaFileObjName, filePart,deletes, false, false, "", objects, failedUploads); err != nil {
			//				//utils.Error("Error occurred in CloudCopy: ", err)
			//				//failedUploads.Store(deltaFileObjName, filePart)
			//			} else {
			//				//AddDatFile(filePart, datFiles)
			//				//SaveDatFileByString(deltaHash, jsonText, utils.GetTopObjectsFolder())
			//				mType = utils.FILE_META_TYPE_DIFF
			//			}
			//		}
			//	}
			//}
			var fileMeta *utils.FileMeta
			utils.Debugf("FileHash:%s, type:%d\n", fileHash, mType)
			//if mType == utils.FILE_META_TYPE_DIFF {
			//	fileMeta = utils.NewFileMeta(mType, deltaHash, 0, s, fileHash)
			//	fileMeta.B = oldHash
			//	utils.Debugf("Data:%s; json:%s\n", oldHash, jsonText)
			//
			//} else {
			fileMeta = utils.NewFileMeta(mType, "", 0, s, fileHash) // createJsonTextForType(fileHash, s, mType); //string(Bytes);
			//}
			if s > 0 {
				setFileMeta(fileMeta, "", folder.Repository, row.LastModified)
				//if err:=CloudCopyLz4File(objFilePath, fileMeta.P, encrypt); err != nil {
				_ = CompressAndUpload(objFilePath, fileMeta,deletes, false, false, "", objects);
			}
		}
	}

	//if complete {
	//	utils.Debugf("================== FileSize:%d, datFile:%s; JSON:\n%s\n", s, fileHash, jsonText)
	//	fm := utils.StringToFileMeta(jsonText);
	//	if(fm != nil) {
	//		fm.SetFileHash( fileHash );
	//		//AddDatFile(fm, datFiles);
	//		//SaveDatFileByString(fileHash, jsonText)
	//		objects.Store(fileHash, fm)
	//	}
	//}

	return ret, filePart
}
func setFileMeta(fileMeta *utils.FileMeta, path string, repo *utils.Repository, lastModified uint32) {
	fileMeta.P = path
	fileMeta.SetRepository( repo )
	fileMeta.SetLastModified( lastModified )
}

func isXDiffApplicable(s int64) bool {
	return s > utils.XDIFF_FILE_SIZE_LOWER && s < utils.XDIFF_FILE_SIZE_UPPER
}

func getOriginalBase(fileHash string) string {
	meta,_ := GetObjectsMeta("", fileHash, utils.GetTopObjectsFolder(), nil) //+ "/" + utils.HashToPath(FileHash) + ".dat";
	if meta != nil && meta.T == utils.FILE_META_TYPE_DIFF {
		return getOriginalBase(meta.B)
	}
	return fileHash
}

func AddObjectByFileHash(userID, userRoot string, fileHash string, opMode int32, objects map[string][]byte) {
	//utils.Debug("Enter AddObjectByFileHash. fileHash: ", fileHash, "; opMode: ", opMode)

	if opMode == utils.MODE_NEW_FILE || opMode == utils.MODE_MODIFIED_CONTENTS || opMode == utils.MODE_REINSTATE_FILE {
		objectsRoot := userRoot + "/objects" // GetServerObjectsDirectory();
		GetObjectsMeta(userID, fileHash, objectsRoot, objects)
		//utils.Debugf("++++++++++++++++ Add to objects. FileHash:%s\n", fileHash)
	}
}

var formatFromExt = map[string]bool{
	"jpg":  true,
	"jpeg": true,
	"png":  true,
	"tif":  true,
	"tiff": true,
	"bmp":  true,
	"gif":  true,
}

func IsImageFile(fileName string, byName bool) bool{
	if(byName) {
		fileName = strings.ToLower(utils.GetDisplayFileName(fileName))
		ext := GetFileExtension(fileName)
		if _, ok := formatFromExt[ext]; ok {
			return true;
		}
	}else {
		if buf, err := ioutil.ReadFile(fileName); err == nil {
			if t, err := filetype.Image(buf); err == nil {
				if _, ok := formatFromExt[t.Extension]; ok {
					return true;
				}
			}
		}
	}
	return false;
}

func createThumbnailsForFolder(folderHash string,folder *utils.ModifiedFolderExt, toEncrypt bool)bool{
	destFile := utils.GetTopObjectsFolder() + utils.HashToPath(folderHash) + utils.EXT_OBJ
	size1 := utils.FileSize(destFile);
	utils.RemoveFile(destFile)

	binFile := utils.GetTopTreeFolder() + utils.HashToPath(folderHash) + utils.EXT_BIN;
	rows := utils.ReadBinAll(binFile, false)
	folderPath :=  utils.GetFolderFullPath(folderHash);

	for _, row := range rows{
		if fileName, foundKey := utils.DbGetStringValue(row.FileNameKey, true) ; foundKey{
			if IsImageFile(fileName, true) {
				utils.Debug("To create thumbnail for ", fileName)
				appendThumbnailForRow(folderPath + "/" + fileName, folderHash, row.ToHashString(), toEncrypt)
			}

		}
	}
	if(folder != nil) {
		for _, row := range folder.GetRows() {
			var indexBinRow utils.IndexBinRow
			indexBinRow.ReadBytes(row.Row, 0)
			fileName := utils.GetDisplayFileName(row.FileName);
			if IsImageFile(fileName, true) {
				utils.Debug("To create thumbnail for ", fileName, "; absFolderPath:", folder.AbsPath)
				appendThumbnailForRow(folder.AbsPath + "/" + fileName, folderHash, indexBinRow.ToHashString(), toEncrypt)

			}
		}
	}

	size2 := utils.FileSize(destFile)
	utils.Debug("Leave createThumbnailsForFolder:", folderHash,"; oldsize:", size1, "; destfile filesize:", size2)
	if(size2 > 0 && size2 != size1){
		return true;
	}else {
		return false;
	}
}

func appendThumbnailForRow(imgFile, folderHash, fileHash string, toEncrypt bool){
	//objFilePath := utils.GetTopObjectsFolder() + utils.HashToPath(fileHash) + utils.EXT_OBJ
	if (!utils.FileExists(imgFile)) {return}
	base := utils.GetTopTmpFolder() + fileHash;
	tmpFile := base + ".jpg"
	src, err := imaging.Open(imgFile, imaging.AutoOrientation(true))
	if err != nil {
		utils.Debug("Couldn't open image file:", imgFile)
		return;
	}
	// Resize the cropped image to width = 200px preserving the aspect ratio.
	src = imaging.Resize(src, utils.THUMB_NAIL_SIZE, 0, imaging.Linear)
	if err != nil {return}
	dir := filepath.Dir(tmpFile)
	if !utils.FileExists(dir) {
		utils.MkdirAll(dir)
	}
	err = imaging.Save(src, tmpFile, imaging.JPEGQuality(75))
	if err != nil {return}
	appendThumbnail( folderHash, fileHash, tmpFile, toEncrypt)
	utils.RemoveFile(tmpFile)
}

func appendThumbnail(folderHash, fileHash, file string, toEncrypt bool)( int, error) {
	var err error;
	base := utils.GetTopObjectsFolder() + utils.HashToPath(folderHash);
	var first byte;
	first = 0;
	if (toEncrypt) {
		first = 1;
		key, err := utils.GetFileEncKey(fileHash);
		if err != nil {
			return  0, err;
		}
		encFile := base + ".e1"
		defer utils.RemoveFile(encFile)
		if err := utils.EncryptFile(file, encFile, &key); err != nil {
			return  0, err;
		}
		file = encFile;
	}
	size := int(utils.FileSize(file));
	bs := utils.FromHex(fileHash)
	destFile := utils.GetTopObjectsFolder() + utils.HashToPath(folderHash) + utils.EXT_OBJ
	dsize := utils.FileSize(destFile)
	var buf []byte;
	buf = append(buf, first)
	buf = append(buf, utils.IntToBytes(size) ...)
	buf = append(buf, bs...);
	if (dsize == 0) {
		if err = utils.WriteBytesSafe(destFile, buf); err != nil {
			utils.Debug("Error is ", err)
		}
	} else {
		_ = utils.AppendBytes(destFile, buf)
	}
	if err = utils.AppendFile(destFile, file); err != nil {
		return  0, err;
	}

	size += len(buf); // 1 + 4 + utils.HASH_BYTE_COUNT;
	return size, nil;
}

func uploadThumbnail(repo * utils.Repository, folderHash string, deletes  *syncmap.Map)(*utils.FileMeta, error) {
	var err error;
	destFile := utils.GetTopObjectsFolder() + utils.HashToPath(folderHash) + utils.EXT_OBJ
	size := utils.FileSize(destFile)
	filePart := utils.NewFileMeta(utils.FILE_META_TYPE_THUMBNAIL, "", 0, size, folderHash)
	filePart.SetRepository( repo )
	filePart.SetLastModified( uint32(time.Now().Unix()) )
	if err = CompressAndUpload(destFile, filePart, deletes, true, true, "",  nil); err != nil {
		return nil, err;
	}

	return filePart, nil;
}

func RestoreThumbnails(folderHash string){
	destFile := utils.GetTopObjectsFolder() + utils.HashToPath(folderHash) + utils.EXT_OBJ
	if(!utils.FileExists(destFile)) {
		if utils.DatFileExists(folderHash) {//utils.FileExists( datFile){
			CopyObjectFromServerTo(destFile, folderHash)
		}
	}
	if(utils.FileExists(destFile)){
		if buf, err := utils.Read(destFile); err == nil {
			len := len(buf)
			start := 0;
			for {
				first := buf[start]
				size := int(utils.BytesToUInt32(buf[start + 1: start+5]));
				start += 5;
				fileHash := fmt.Sprintf("%x", buf[start:start+utils.HASH_BYTE_COUNT]);
				start += utils.HASH_BYTE_COUNT;
				tmpFile := utils.GetTopObjectsFolder() + utils.HashToPath(folderHash) +  "_" + fileHash +".png"
				go writeThumbnail(tmpFile, folderHash, fileHash,  buf[start:start+size], first == 1)
				start += size;
				if (start >= len) {
					break;
				}

			}

		}
	}
}

func writeThumbnail(tmpFile , folderHash, fileHash string, buf []byte, isEncrypted bool){
	if ! utils.FileExists(tmpFile) {
		utils.WriteBytesSafe(tmpFile, buf);
		if (isEncrypted) { //encrypted
			key, err := utils.GetFileEncKey(fileHash);
			if err != nil {
				fmt.Println("Cannot get encryption key")
				return;
			}
			tmpFile2 := utils.GetTopObjectsFolder() + utils.HashToPath(folderHash) + "_" + fileHash + ".t2"
			if err := utils.DecryptFile(tmpFile, tmpFile2, &key); err != nil {
				return;
			}
			//utils.RemoveFile(tmpFile)
			if src, err := imaging.Open(tmpFile2) ; err == nil {
				_ = imaging.Save(src, tmpFile)
			}
			utils.RemoveFile(tmpFile2)
			//utils.Rename(tmpFile2, tmpFile)
		}
	}

}
