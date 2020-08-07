// Copyright (c) 2020, Yanbin (Henry) Zheng <ybzheng@gmail.com>
// All rights reserved.
//
// Use of this source code is governed by a AGPLv3 license that can be
// found in the LICENSE file.
package client

import (
	"errors"
	"github.com/panjf2000/ants"
	"sync"
	utils "github.com/anysync/server/utils"
)

//Do it on the local server side
func FixRepo(folder, hash string) {
	fileName, err := DoFixRepo(folder, hash)

	if(err != nil){
		utils.SendToLocal("nfixed:" + fileName)
	}else{
		utils.SendToLocal("fixed:" + fileName)
	}
}
func DoFixRepo(folder, hash string) (string,error){
	binFile := utils.GetTopTreeFolder() + utils.HashToPath(folder) + utils.EXT_BIN;
	row:=utils.GetRowByHash(binFile, hash)
	fileName, err := GetFullFileNameByKey(folder, row.FileNameKey)
	if(err != nil){
		return "", errors.New("local file does not exist")
	}
	utils.Debug("file name is", fileName)
	if(!utils.FileExists(fileName)){
		return fileName,errors.New("local file does not exist")
	}
	fileMeta := utils.GetDatObject(hash);// utils.ReadString(datFile)
	if(fileMeta == nil){
		return fileName,errors.New("dat file is not correct, hash is " + hash)
	}

	cp := utils.DecodePath(fileMeta.P)
	fileHash := utils.GetFileHash( fileName, "")
	if(fileHash != hash){
		return fileName, errors.New("local file is not the same file as the cloud")
	}
	objName := utils.GetTopObjectsFolder() + utils.HashToPath(fileHash) + utils.EXT_OBJ
	utils.CopyFile(fileName, objName)
	fileMeta.SetFileHash( fileHash)
	repos:=utils.GetAllRepositoryList(false);
	fileMeta.SetRepository( repos[0] )
	fileMeta.SetNoStaging( true );
	if err := CompressAndUpload(objName, fileMeta, nil, !cp.Encrypted, !cp.Compressed, "",  nil); err != nil {
		return fileName, errors.New("cannot upload to cloud at this moment")
	}
	data := make(map[string][]byte)
	data["hash"] = []byte(hash)
	if val, f := utils.GetFileID(cp.Path) ; f {
		data["id"] = []byte(val)
		utils.Debug("Found ID:", val , "; For fileMeta.CloudPath:", cp.Path)
		utils.UpdateFileID(fileMeta, val)
		utils.UpdateDatFile(hash, []byte(utils.FileMetaToString(fileMeta)), "")
		//utils.WriteString(datFile, utils.FileMetaToString(fileMeta))
	}
	utils.ClearFileNameToID()
	utils.CallSendData("updateMeta", nil, data, nil, nil)
	return fileName,nil;
}



func GetFullFileNameByKey(folderHash, fileNameKey string) (string, error){
	dir := utils.GetFolderFullPath(folderHash)
	name, b := utils.DbGetStringValue(fileNameKey, true)
	if (!b) {
		return "", errors.New("file name is not found in folder: " + dir)
	}
	fileName := dir + "/" + name;
	return fileName, nil;
}

type RepoNotSynced struct{
	repo *utils.Repository;
	notsynced * []string;
}

func verifyRepositories() []string{
	list := utils.GetRepositoryList()
	config := utils.LoadConfig()
	config.Mode = utils.CONFIG_MODE_BIDIRECTION
	var notsynced []string
	var wg sync.WaitGroup
	p, _ := ants.NewPoolWithFunc(50, func(i interface{}) {
		doCheckRepo(i)
		wg.Done()
	})
	defer p.Release()

	for _, repo := range list {
		if repo.Hash == utils.SHARED_HASH {
			continue
		}
		checkRepo(p, &wg, repo, &notsynced)
		if len(notsynced) > 0{
			return notsynced
		}
	}
	wg.Wait()
	return nil
}

func checkRepo(p *ants.PoolWithFunc, wg * sync.WaitGroup, repo *utils.Repository, ret * []string) {
	d := RepoNotSynced{
		repo:repo,
		notsynced: ret,
	};
	if(p.Running() < p.Cap()) {
		wg.Add(1)
		p.Invoke(&d)
	}else{
		doCheckRepo(&d)
	}
}
func doCheckRepo(i interface{}) {
	d := i.(*RepoNotSynced)
	repo := d.repo
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
		if err := ReadBinFileProcessRow(utils.GetTopTreeFolder()+"/"+path+".bin", checkRow, "", restoreDir, hash, name, repo.HashSuffix, d.notsynced); err != nil {
			return
		}
	}
	return
}
func checkRow(io *utils.IndexBinRow, args ...interface{}) error {
	if io.Index == 0 || utils.IsFileModeDeleted(io.FileMode) {
		return nil
	}
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
	restoreRootDir = args[1].(string)
	repoName := args[3].(string)
	hashSuffix := args[4].(string)
	notsynced := args[5].(*[]string)
	dest := restoreRootDir + relativePath + "/" + fileName
	utils.SendMsg("To verify file .../" + utils.Basename2(dest) + "/" + fileName)
	fName, t, _ := GetFileNameModTimeAndSize(dest)
	if t > 0 && fName != fileName {
		fileName, _ = fixDuplicateFileName(fileName, io.Index)
		dest = restoreRootDir + "/" + relativePath + "/" + fileName
	}
	if utils.IsFileModeDirectory(io.FileMode) {
		traverseTree2(restoreRootDir, sha, relativePath+"/"+fileName, repoName, hashSuffix, notsynced)
	} else if utils.IsFileModePipe(io.FileMode) {
	} else { //it's file or pipe
		//fmt.Printf("fileInfo:%s; dest:%s\n", fileInfo, dest);
		if(io.FileSize == 0 || sha == utils.ZERO_HASH ){
			return nil
		}
		var fileHash string
		meta := utils.GetDatObject(sha)
		//fmt.Println("Type:", meta.T, "; File:", dest)
		if(meta == nil){
			*notsynced = append(*notsynced, dest)
			return nil
		}
		ftype := meta.T

		if ftype == utils.FILE_META_TYPE_PACK_ITEM {
			meta = utils.GetDatObject(meta.P);
		}else{
			if utils.FileExists(dest) {
				fileHash = utils.GetFileHash(dest, hashSuffix)
				//utils.Debug("fileHash: ", fileHash, "; io.bin.hash: ", sha)
			}
			if(sha != fileHash){
				*notsynced = append(*notsynced, dest)
				return nil
			}
		}

		if meta != nil  {
			if(meta.T == utils.FILE_META_TYPE_CHUNKS){
				hashArr := GetChunksHash(meta.P)
				for _,h := range hashArr{
					m := utils.GetDatObject(h)
					if(m.C > 0){
						p := utils.DecodePath(m.P)
						if len(p.Hash) == 0 {
							*notsynced = append(*notsynced, dest)
						}
					}else if(m.T != utils.FILE_META_TYPE_PACK_ITEM){
						*notsynced = append(*notsynced, dest)
					}

				}

			} else if meta.C > 0 {
				p := utils.DecodePath(meta.P)
				if len(p.Hash) == 0 {
					utils.Debug("File ", dest, " is not synced.")
					*notsynced = append(*notsynced, dest)
				}
			}
		}

	}

	return nil
}

func traverseTree2(restoreRootDir string, hash string, originalPath string, repoName, hashSuffix string, notsynced *[]string) error {
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
		if err := ReadBinFileProcessRow(utils.GetTopTreeFolder()+"/"+path+".bin", checkRow, originalPath, restoreRootDir, hash, repoName, hashSuffix, notsynced); err != nil {
			return err
		}
	}
	return nil
}
