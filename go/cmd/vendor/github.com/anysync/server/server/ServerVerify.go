// Copyright (c) 2020, Yanbin (Henry) Zheng <ybzheng@gmail.com>
// All rights reserved.
//
// Use of this source code is governed by a AGPLv3 license that can be
// found in the LICENSE file.

package server

import (
	client "github.com/anysync/server/client"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
	utils "github.com/anysync/server/utils"
)


func DeepVerifyOnServer(verifyDb *sql.DB, user *utils.UserAccount, hash string) *utils.ErrorWithCode {
	userID := fmt.Sprintf("%d", user.ID)
	userRoot := utils.GetUserRootOnServer(userID)
	binFile := userRoot + "/tree/" + utils.HashToPath(hash) + utils.EXT_BIN
	rows := utils.ReadBin(binFile, utils.FILTER_NONE, nil)

	if err := VerifyRows(verifyDb, user, rows, hash); err != nil {
		utils.Debug("DeepVerify error is ", err)
		return err
	}

	return nil
}

func VerifyRows(verifyDb *sql.DB, user *utils.UserAccount,  rows []*utils.IndexBinRow, folderHash string) *utils.ErrorWithCode {

	for _, row := range rows {
		if utils.IsFileModeDirectory(row.FileMode) {
			if b := DeepVerifyOnServer(verifyDb, user, row.ToHashString()); b != nil {
				return b
			}
		} else {
			if err := VerifyFile(verifyDb, user, row, folderHash); err != nil {
				return err
			}
		}
	}

	return nil
}

func VerifyFile(verifyDb *sql.DB, user *utils.UserAccount, row *utils.IndexBinRow, folderHash string) *utils.ErrorWithCode {
	if row.FileSize == 0 {
		return nil
	}
	userID := fmt.Sprintf("%d", user.ID)
	hash := row.ToHashString()
	code := 0
	fileMeta, err := GetFileMetaOnServer(userID, hash)
	if err != nil {
		return utils.NewErrorWithCode("dat file not found1: "+hash + "; userID:" + userID, code)
	}
	if fileMeta.T == utils.FILE_META_TYPE_PACK_ITEM {
		return verifyPackFile(verifyDb, userID, user.Bucket, folderHash, hash, row.FileNameKey, fileMeta)
	} else if fileMeta.T == utils.FILE_META_TYPE_CHUNKS { //multi-part file
		hashes := client.GetChunksHash(fileMeta.P)
		for _, h := range hashes {
			if cfileMeta, err := GetFileMetaOnServer(userID, h); err != nil {
				return utils.NewErrorWithCode("dat file not found2: "+fileMeta.P + "; userID:" + userID, code)
			} else {
				if cfileMeta.T == utils.FILE_META_TYPE_PACK_ITEM {
					return verifyPackFile(verifyDb, userID, user.Bucket, folderHash, hash, row.FileNameKey, cfileMeta)
				}
				if len(fileMeta.P) == 0 {
					utils.Debug("Empty fileMeta.P, hash:", hash)
				}
				if ec := checkCloudByFileID(verifyDb, user.Bucket, cfileMeta.P); ec != nil {
					//fileName, _ := client.GetFullFileNameByKey(folderHash, row.FileNameKey) cannot get fileName on the server side
					return handleCloudError(folderHash, hash, folderHash + ":" + row.FileNameKey, ec)
				}
			}
		}
		return nil
	} else {
		if len(fileMeta.P) == 0 {
			utils.Debug("Empty fileMeta.P, hash:", hash)
		}
		ec := checkCloudByFileID(verifyDb, user.Bucket, fileMeta.P)
		if ec == nil {
			return nil
		} else {
			//fileName, _ := client.GetFullFileNameByKey(folderHash, row.FileNameKey) cannot get fileName on the server side
			return handleCloudError(folderHash, hash, folderHash + ":" + row.FileNameKey, ec)
		}
	}
}

func verifyPackFile(verifyDb *sql.DB, userID, userRoot, folderHash, hash, fileNameKey string, fileMeta *utils.FileMeta) *utils.ErrorWithCode {
	code := 0
	if pfileMeta, err := GetFileMetaOnServer(userID, fileMeta.P); err != nil {
		return utils.NewErrorWithCode("dat file not found3: "+fileMeta.P + "; userID:" + userID, code)
	} else {
		if len(pfileMeta.P) == 0 {
			utils.Debug("Empty fileMeta.P, hash:", hash)
		}
		if ec := checkCloudByFileID(verifyDb, userRoot, pfileMeta.P); ec != nil {
			fileName, _ := client.GetFullFileNameByKey(folderHash, fileNameKey)
			return handleCloudError(folderHash, hash, fileName, ec)
		} else {
			return nil
		}
	}
}


func handleCloudError(folderHash, fileHash, fileName string, ec * utils.ErrorWithCode) * utils.ErrorWithCode{
	if(ec.Code == 1000){
		return utils.NewErrorWithCode(fmt.Sprintf("This file is not right on cloud: %s", fileName), ec.Code)
	}else if(ec.Code == 404){
		e := utils.NewErrorWithCode("cannot find file on the cloud: " + fileName, ec.Code);
		e.Data = make(map[string][]byte)
		e.Data["folder"] = []byte(folderHash)
		e.Data["hash"] = []byte(fileHash)
		return e;
	}else{
		return ec;
	}
}


func checkCloudByFileID(verifyDb *sql.DB, bucketName,  path string)*utils.ErrorWithCode{
	//code := 0;
	////utils.Debug("checkCloudByFileID: path:", path)
	//cp := utils.DecodePath(path)
	//var pos int;
	//if(cp.RemoteName == utils.REMOTE_STORAGE_NAME) {
	//	//path example:  1001:AnySync1/b330d3d11aa4447649020adbd389ea6ed5a9b751299c859e08106fcb/objects/35/ea/2d/79bcf5c0734edb77a4358834ed68d73281ee81b26356347717.obj@ef2288c819c3d12a5009f9a85e1a232d033b9be0#4_zee48aadaf1be739e60250918_f108842cf70647ab7_d20191228_m010713_c000_v0001063_t0049
	//	now := uint32(time.Now().Unix());
	//	bs := utils.Uint32ToBytes(now);
	//	pos = strings.Index(path, utils.META_PATH_ID_SEPARATOR)
	//	if (pos < 0) {
	//		_, _, err := GetCloudFileInfoByFileName(bucketName, cp.FileName)
	//		if err == nil {
	//			//if (sha != cp.Hash) {
	//			//	return utils.NewErrorWithCode("This file is not right on cloud", 1000)
	//			//}
	//			utils.SetValue(verifyDb, cp.Hash, bs)
	//			//verifyDb.Put([]byte(cp.Hash), bs,  nil)
	//			return nil
	//		}else{
	//			return  utils.NewErrorWithCode("file is not found, path1 is " + cp.FileName, code)
	//		}
	//		return utils.NewErrorWithCode("dat file is not correct, path1 is " + path, code)
	//	}
	//	fileID := cp.FileID // path[pos+1: ]
	//	fileHash := cp.Hash // fileID[0:pos]
	//	if val, found := utils.GetValue(verifyDb, fileHash); found{
	//	//if val, err := verifyDb.Get([]byte(fileHash), nil ) ; err == nil{
	//		n := utils.BytesToUInt32(val);
	//		if now - n < 86400*5 {
	//			return nil;
	//		}
	//	}
	//	sha, err := GetCloudFileInfo(bucketName, fileID);
	//	code = 200;
	//	utils.Debug("File ID is", fileID, "; FileHash:", fileHash, "; httpCode:", code)
	//	if (err == nil) {
	//		if (sha != fileHash) {
	//			return utils.NewErrorWithCode("This file is not right on cloud", 1000)
	//		}
	//		utils.SetValue(verifyDb, fileHash, bs)
	//		//verifyDb.Put([]byte(fileHash), bs,  nil)
	//		//utils.WriteString(okFile, fmt.Sprintf("%s", fileHash))
	//	}
	//}
	return nil;
}




func FindAbandoned(){
	FindAbandonedBinFiles()
	FindAbandonedObjects()
}

//Find object files which are not referenced
//Method: Iterate thru bin files, read the bin file and load all its file rows, find the obj file of each file and rename it
// to .tad file. After it's done, seach all *.dat files in objects directory to find the files that are not referenced.
func FindAbandonedObjects(){
	//note: rename *.tad to *.dat recursively:       find . -exec rename 's|tad|dat|' {} +
	t1 := uint32(time.Now().Unix())
	path := utils.GetTopTreeFolder();
	topHashes := getTopHashes();
	utils.Debug("Top hashes:", topHashes)
	total := 0;
	filepath.Walk(path, func(CurrentPath string, info os.FileInfo, err error) error {
		if !info.IsDir() && strings.HasSuffix(CurrentPath, utils.EXT_BIN) {
			rows:=utils.ReadBin(CurrentPath, utils.FILTER_FILE_ONLY, nil)
			for _, row := range rows {
				if(row.FileSize == 0){
					continue;
				}
				hash := row.ToHashString();
				renameDatFile(hash, CurrentPath)
				total ++;
			}
		}
		return err
	})
	t2 := uint32(time.Now().Unix())
	fmt.Println("Done time: ", (t2 - t1), "; total: ", total)
}

func renameDatFile(hash string, binPath string){
	//objDir := utils.GetTopObjectsFolder();
	//datFile := objDir + utils.HashToPath(hash) + utils.EXT_DAT;
	fileMeta := utils.GetDatObject(hash);// utils.GetFileMetaForFile(datFile);

	if( fileMeta != nil){
		//tadFile := objDir + utils.HashToPath(hash) + ".tad";
		//utils.Debug("To rename file:", datFile, " to tad:" , tadFile)

		if(fileMeta.T == utils.FILE_META_TYPE_CHUNKS){
			chunks := client.GetChunksHash(fileMeta.P)
			for _, c := range chunks{
				renameDatFile(c, binPath)
			}
		}else if(fileMeta.T == utils.FILE_META_TYPE_PACK_ITEM){
			renameDatFile(fileMeta.P, binPath)
		}

		utils.ObjectsDbSetStateValue(hash, 2)
		//utils.Rename(datFile, tadFile)
	}else{
		utils.Warn("Dat file does not exist:", hash, "; and its bin file:", binPath)
	}
}

//Find bin files which are not referenced
//Method: iterate thru folders, check each bin file and find its parent files, until its parent node is one of valid top nodes
func FindAbandonedBinFiles(){
	t1 := uint32(time.Now().Unix())
	path := utils.GetTopTreeFolder();
	topHashes := getTopHashes();
	utils.Debug("Top hashes:", topHashes)
	total := 0;
	filepath.Walk(path, func(CurrentPath string, info os.FileInfo, err error) error {
		if !info.IsDir() && strings.HasSuffix(CurrentPath, utils.EXT_BIN) {
			//utils.Debug("BinFile:", CurrentPath)
			hash:= client.GetHashFromPath(CurrentPath)
			if(hash == utils.NULL_HASH || topHashes[hash] != ""){
				return nil;
			}
			total ++;
			var list []string;
			list = append(list, CurrentPath)
			if( !isRootFileValid(CurrentPath, topHashes, list)){
				fmt.Errorf("Abandoned bin file: %s\n", CurrentPath)
			}
		}
		return err
	})
	t2 := uint32(time.Now().Unix())
	fmt.Println("Done time: ", (t2 - t1), "; total: ", total)
}


func isRootFileValid(binFile string, topHashes map[string]string, list []string)bool{
	if row:=utils.GetRowAt(binFile, 0); row != nil{
		parentHash := row.ToHashString()
		if _, ok := topHashes[parentHash]; ok{
			return true;
		}
		binFile = utils.GetTopTreeFolder() + utils.HashToPath(parentHash)  + utils.EXT_BIN;
		list = append(list, binFile)
		return isRootFileValid(binFile, topHashes, list)
	}else{
		utils.Debug("Wrong binFile:", binFile, "; path list: ", list)
		return false;
	}

}

func getTopHashes() map[string]string{
	repos := utils.GetRepositoryList();
	ret := make(map[string]string)
	for _, r := range repos{
		ret[r.Hash] = r.Name
	}
	return ret;
}

func GetFileMetaOnServer(userID, hash string)(*utils.FileMeta, error) {
	fileMeta, _ := utils.GetServerDatObjectAndContent(userID, hash);
	if fileMeta != nil  {
		return fileMeta, nil
	}else{
		return nil, errors.New("dat file not found: " + hash);
	}
}
