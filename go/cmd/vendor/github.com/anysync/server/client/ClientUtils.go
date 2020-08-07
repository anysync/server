// Copyright (c) 2020, Yanbin (Henry) Zheng <ybzheng@gmail.com>
// All rights reserved.
//
// Use of this source code is governed by a AGPLv3 license that can be
// found in the LICENSE file.
package client
import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/golang/protobuf/proto"
	"os"
	"strings"
	utils "github.com/anysync/server/utils"
)


//the fileHash is required for pack_item type file.
func GetCloudFile(objFilePath string, fileHash string, destFile string) error {
	meta := utils.GetDatObject(fileHash) // utils.StringToFileMeta(content)
	if meta == nil {
		return errors.New("no dat info for " + fileHash)
	}
	ftype := meta.T
	var err error
	if ftype == utils.FILE_META_TYPE_REGULAR || ftype == utils.FILE_META_TYPE_THUMBNAIL || ftype == utils.FILE_META_TYPE_PACK || ftype == utils.FILE_META_TYPE_CHUNK_ITEM {
		utils.Debug("src:", meta.P, "; dest:", destFile)
		if err := decryptAndRestoreTo(meta, fileHash, destFile); err != nil {
			return err
		}
	} else if ftype == utils.FILE_META_TYPE_PACK_ITEM {
		objFile := utils.GetTopObjectsFolder() + utils.HashToPath(meta.P) + utils.EXT_OBJ
		if !utils.FileExists(objFile) {
			if err = GetCloudFile(objFile, meta.P, objFile); err != nil {
				return err
			}
		}
		packMeta := utils.GetDatObject(meta.P) //  utils.StringToFileMeta(packContent)
		if packMeta == nil {
			return errors.New("no dat info for " + meta.P)
		}
		isEncrypted := IsObjFileEncrypted(packMeta.P)
		utils.ExtractFile(objFile, meta.F, meta.S, destFile, isEncrypted, fileHash, meta.K)
	} else if ftype == utils.FILE_META_TYPE_CHUNKS { //multi-part file
		dir := utils.RemoveLastUrlPathComponent(objFilePath)
		if !utils.FileExists(dir) {
			utils.MkdirAll(dir)
		}
		paths, err := base64.StdEncoding.DecodeString(meta.P)
		if err != nil || len(paths) == 0 {
			return err
		}
		num := len(paths) / (utils.HASH_BYTE_COUNT)
		if utils.FileExists(objFilePath) {
			utils.RemoveFile(objFilePath)
		}
		//utils.Debugf("paths.len:%d, num:%d\n", len(paths), num)
		for i := 0; i < num; i++ {
			hashBytes := paths[i*utils.HASH_BYTE_COUNT : utils.HASH_BYTE_COUNT*(i+1)]
			hash := fmt.Sprintf("%x", hashBytes)
			utils.Debugf("fileHash: %s\n", hash)
			partObjFile := utils.GetTopObjectsFolder() + utils.HashToPath(hash) + utils.EXT_OBJ
			if !utils.FileExists(partObjFile) {
				if err = GetCloudFile(partObjFile, hash, partObjFile); err != nil {
					return err
				}
			}
			utils.AppendFile(objFilePath, partObjFile)
		}
		utils.CopyFile(objFilePath, destFile)
	} else if ftype == utils.FILE_META_TYPE_DIFF {
		if len(meta.P) == 0 || len(meta.B) == 0 {
			return nil
		}
		baseObjFile := utils.GetTopObjectsFolder() + utils.HashToPath(meta.B) + utils.EXT_OBJ
		if !utils.FileExists(baseObjFile) {
			GetCloudFile(baseObjFile, "", baseObjFile)
		}
		deltaObjFile := utils.GetTopObjectsFolder() + utils.HashToPath(fileHash) + utils.EXT_OBJ
		if !utils.FileExists(deltaObjFile) {
			GetCloudFile(deltaObjFile, meta.P, deltaObjFile)
		}

		if err = patch(baseObjFile, objFilePath, deltaObjFile); err != nil {
			return err
		}
		utils.CopyFile(objFilePath, destFile)
	}
	return nil
}

func decryptAndRestoreTo(meta *utils.FileMeta, fileHash, destFile string) error {
	if meta.P == "" {
		return nil
	} //src file doesn't exist
	skipDecrypt := false
	if meta.T == utils.FILE_META_TYPE_PACK {
		skipDecrypt = true
	}
	if err := CloudCopyUnLz4File(meta, destFile, skipDecrypt, fileHash); err != nil {
		utils.Error("Error occurred in CloudCopyUnLz4File: ", err, ". meta.P:", meta.P)
		return err
	}
	return nil
}

func CallShareFolder(name, folderHash, to, includes string) {
	utils.Debug("Enter CallShareFolder, name: ", name)
	data := make(map[string][]byte)
	data["hash"] = []byte(folderHash)
	data["to"] = []byte(to)           //todo: needs to check if there any existing shares
	pubKeys, err := getAllPubKeys(to) //get public pubKeys of all shared users
	utils.Debug("pubkeys.size: ", len(pubKeys))
	if err != nil {
		return
	}
	tk, err := utils.GetFileEncKey(folderHash) // sharekey must be deterministic, otherwise it causes problem when a folder has multiple shares.    utils.GenerateRandomBytes(32)
	sharedFolderKey := tk[:]
	subPath := utils.HashToPath(utils.SHARED_HASH)
	binFile := utils.GetTopTreeFolder() + subPath + ".bin"
	fileSize := utils.FileSize(binFile)
	index := uint32(fileSize / utils.FILE_INFO_BYTE_COUNT)

	datFiles, nameFiles, _ := processDatNames(folderHash, includes, sharedFolderKey, folderHash)
	var tasks []*utils.WriteTask

	sharedFolder := utils.ShareFolder{}
	attribs := make(map[string][]byte)
	sharedFolder.MemberKeys = make(map[string]string)
	sharedFolder.Hash = folderHash // utils.SHARED_HASH;
	sharedFolder.Name = name       //"Shared 1"
	sharedFolder.ID = utils.GenerateRandomHash()
	sharedFolder.Includes = includes
	sharedFolder.HashSuffix = utils.GetHashSuffix()
	config := utils.LoadConfig()
	sharedFolder.Owner = config.User
	sharedFolder.EncryptionLevel = 1
	if len(data["public"]) > 0 {
		sharedFolder.EncryptionLevel = 0
	}

	myPubKey, _ := utils.GetClientPubKey()
	myPrivKey, _ := utils.GetClientPrivKey()
	var myPub, myPriv [32]byte
	copy(myPub[:], []byte(myPubKey))
	copy(myPriv[:], []byte(myPrivKey))

	pubKeys[config.User] = myPubKey
	for user, pkey := range pubKeys {
		utils.Debug("PubKey2:", fmt.Sprintf("%x", pkey))
		e := utils.RsaEncrypt(pkey, sharedFolderKey, &myPriv, &myPub)
		sharedFolder.MemberKeys[user] = hex.EncodeToString(e)
	}
	sharedFolder.HashSuffix = utils.GetHashSuffix()
	shareBytes := utils.GetShareInBytes(&sharedFolder)
	attribs[utils.ATTR_SHARE] = shareBytes
	data["id"] = []byte(sharedFolder.ID) // string(shareBytes)

	fileNameKey := utils.CalculateFileNameKey(name, true, utils.SHARED_HASH, utils.GetHashSuffix())
	addShareFolderName(nameFiles, sharedFolderKey, folderHash, fileNameKey, name)
	nameTask := CreateAddFileNameTask("", CreateRow(fileNameKey, sharedFolder.Name)) //??? ZYB 8/14
	tasks = append(tasks, nameTask)

	row := createRowWithHash(index, utils.TYPE_DIRECTORY, fileNameKey, folderHash)
	appendTask, _ := CreateAppendBinRowTask(&tasks, utils.SHARED_HASH, utils.SHARED_HASH, index, row, attribs, "", "", utils.GetTopTreeFolder())
	ExecuteTasks(tasks, true,  utils.LoadConfig().User)
	appendTask.Index = 0
	utils.Debug("CallShareFolder. tasks.len:", len(tasks))
	utils.CallSendData("shareFolder", tasks, data, datFiles, nameFiles)
	utils.SendToLocal("reloadTree")
}

func processDatNamesFunc(io *utils.IndexBinRow, args ...interface{}) error {
	shareFolderKey := args[0].([]byte)
	datFiles := args[1].(map[string][]byte)
	nameFiles := args[2].(map[string][]byte)
	folderHash := args[3].(string)
	realNameFiles := args[4].(map[string]string)
	includes := args[5].(map[uint32]bool)
	hash := io.ToHashString()
	if len(includes) > 0 {
		if _, ok := includes[io.Index]; !ok {
			return nil
		}
	}
	fileMode := io.FileMode
	if utils.IsFileModeDeleted(fileMode) || utils.IsFileModeDirectory(fileMode) {
		return nil
	}
	fileNameKey := io.FileNameKey
	meta := utils.GetDatObject(hash) // utils.StringToFileMeta(content)

	GetObjectsMeta("", hash, utils.GetTopObjectsFolder(), datFiles)

	k := setFileMetaKey(shareFolderKey, meta, hash, folderHash)
	text := utils.FileMetaToString(meta)
	datFiles[hash] = []byte(text)
	utils.UpdateDatFile(hash, []byte(text), "")
	//utils.WriteBytesSafe(datFile, []byte(text))

	if bs, found := utils.DbGetValue(fileNameKey); found {
		realFileName, _ := utils.DbGetStringValue(fileNameKey, true)
		text := utils.SetFileNameKey(fileNameKey, string(bs), realFileName, folderHash, &k)
		nameFiles[fileNameKey] = []byte(text)
		realNameFiles[hash] = realFileName
	}

	return nil
}

func setFileMetaKey(shareFolderKey []byte, meta *utils.FileMeta, fileHash, folderHash string) [32]byte {
	var k [32]byte
	copy(k[:], shareFolderKey)
	if len(meta.K) == 0 {
		var buf []byte
		buf = append(buf, utils.FromHex(folderHash)...)
		encKey, _ := utils.GetFileEncKey(fileHash)
		buf = append(buf, utils.EncryptText(string(encKey[:]), &k)...)
		meta.K = append(meta.K, base64.StdEncoding.EncodeToString(buf))
	}
	return k
}

func processDatNames(folderHash, includesText string, shareFolderKey []byte, newFolderHash string) (map[string][]byte, map[string][]byte, map[string]string) {
	base := utils.GetTopTreeFolder() + utils.HashToPath(folderHash)
	binFile := base + utils.EXT_BIN // ".bin";
	datFiles := make(map[string][]byte)
	nameFiles := make(map[string][]byte)
	realNameFiles := make(map[string]string)
	var includes map[uint32]bool
	if len(includesText) > 0 {
		tokens := strings.Split(includesText, ",")
		includes = make(map[uint32]bool) //[]uint32
		for _, token := range tokens {
			includes[utils.ToUint32(token)] = true
		}
	}
	ReadBinFileProcessRow(binFile, processDatNamesFunc, shareFolderKey, datFiles, nameFiles, newFolderHash, realNameFiles, includes)

	return datFiles, nameFiles, realNameFiles
}

func GetObjectsMeta(userID, hash string, topDirectory string, objects map[string][]byte) (*utils.FileMeta, []byte) {
	var meta *utils.FileMeta
	var content []byte
	if userID == "" {
		meta, content = utils.GetDatObjectAndContent(hash) // utils.StringToFileMeta(content)
	} else {
		meta, content = utils.GetServerDatObjectAndContent(userID, hash)
	}

	if objects != nil && meta != nil {
		if meta.T == utils.FILE_META_TYPE_CHUNKS {
			paths, err := base64.StdEncoding.DecodeString(meta.P)
			if err != nil || len(paths) == 0 {
				return nil, []byte("")
			}
			num := len(paths) / (utils.HASH_BYTE_COUNT)
			for i := 0; i < num; i++ {
				hashBytes := paths[i*utils.HASH_BYTE_COUNT : utils.HASH_BYTE_COUNT*(i+1)]
				chunkHash := fmt.Sprintf("%x", hashBytes)
				GetObjectsMeta(userID, chunkHash, topDirectory, objects)
			}
		} else if meta.T == utils.FILE_META_TYPE_PACK_ITEM { //get its parent dat
			packHash := meta.P
			GetObjectsMeta(userID, packHash, topDirectory, objects)
		}
		objects[hash] = content
	} else {
		utils.Debug("ERROR. Failed to get meta obj. hash: ", hash)
	}
	return meta, content
}


func addShareFolderName(nameFiles map[string][]byte, sharedFolderKey []byte, folderHash, fileNameKey, realFileName string) {
	var k [32]byte
	copy(k[:], sharedFolderKey)
	text := utils.EncryptFileNameKey(fileNameKey, realFileName, folderHash, &k)
	nameFiles[fileNameKey] = []byte(text)
}

func CallShareFolderInit(attribs map[string][]byte) {
	if attribs == nil {
		utils.Error("Enter CallShareFolderInit, attribs is nil")
		return
	}
	shareFolder := utils.GetShareFromBytes(attribs[utils.ATTR_SHARE])
	data := make(map[string][]byte)
	data["owner"] = []byte(shareFolder.Owner)
	data["hash"] = []byte(shareFolder.Hash)
	data["id"] = []byte(shareFolder.ID)
	utils.Debug("sharefolder.members.len: ", len(shareFolder.MemberKeys), "; data is", data)
	if response, err := utils.CallSendData("getShareInit", nil, data, nil, nil); err == nil {
		utils.Debug("getShareInit returned. data.zip.len:", len(response.Data["zip"]))
		zip := response.Data["zip"]
		folder := utils.GetTopTmpFolder() + utils.GenerateRandomHash()
		zipFile := folder + ".tar.lz4"
		utils.Debug("zip file:", zipFile, "; folder:", folder)
		utils.WriteBytesSafe(zipFile, []byte(zip))
		defer utils.RemoveFile(zipFile)
		defer utils.RemoveAllFiles(folder)
		utils.UnzipTo(zipFile, folder)
		requestFile := folder + "/init/request"
		bs, _ := utils.ReadString(requestFile)

		in := utils.UserRequest{}
		if proto.Unmarshal([]byte(bs), &in) == nil {
			DoSaveObjectsToFile(in.Data2, utils.GetAppHome(), false, false, "")
			for fileNameKey, val := range in.Data3 {
				utils.NamesDbSetStringValue(fileNameKey, string(val))
			}

		}

		config := utils.LoadConfig()
		if shareFolder.Owner != config.User { //is not owner
			binFile := folder + "/init/bin"
			if config.Mode != utils.CONFIG_MODE_PLACEHOLDER && utils.FileExists(binFile) {
				localBinFile := utils.GetTopTreeFolder() + utils.HashToPath(shareFolder.Hash) + utils.EXT_BIN
				utils.CopyFile(binFile, localBinFile)
				utils.Debug("Copy bin to ", localBinFile)
				UpdateLocalShareFolder(shareFolder.Hash, localBinFile, shareFolder.Includes)
			}
		}

		utils.CopyDir(folder+"/objects/", utils.GetTopObjectsFolder())

		utils.Debug("Reach here.")
	} else {
		utils.Debug("getShareInit error is", err)
	}

	utils.SendToLocal("reloadTree")
}

func UpdateLocalShareFolder(folderHash, binFile, includes string) {
	local := utils.GetTopShareFolder()
	folder := local + utils.HashToPath(folderHash) + "/"
	utils.MkdirAll(folder)
	var is []uint32
	if len(includes) > 0 {
		is = utils.StringToUints(includes)
	}
	rows := utils.ReadBin(binFile, utils.FILTER_FILE_ONLY, is)
	for _, row := range rows {
		hash := row.ToHashString()
		if fileName, found := utils.DbGetStringValue(row.FileNameKey, true); found {
			utils.Debug("UpdateLocalShareFolder. hash: ", hash, "; fileName: ", folder+fileName)
			if err := CopyObjectFromServer(hash); err == nil {
				subPath := utils.HashToPath(hash)
				objFile := utils.GetTopObjectsFolder() + subPath + utils.EXT_OBJ
				utils.CopyFile(objFile, folder+fileName)
			}
		}
	}
}

func ResetUserAndInitLocalServer(userID string) {
	utils.ResetUser(userID)
	initializeLocalServer()
}

func initializeLocalServer() {
	createFolders()
	//utils.Log = utils.NewLogger(utils.GetLogsFolder() + "/client.log");
	//utils.OpenDB(utils.GetDataFolder() + "data.db")
	HandleIncompleteTasks()

	argsWithoutProg := os.Args[1:]
	n := len(argsWithoutProg)
	if n == 1 && argsWithoutProg[0] == "rescan" {
		StartRescan(nil)
	}
	go StartRescanTimer()
}

func GetOpModeString(op uint8) string {
	if utils.MODE_NEW_FILE == op {
		return "New file"
	} else if utils.MODE_NEW_DIRECTORY == op {
		return "New directory"
	} else if utils.MODE_DELETED_FILE == op || utils.MODE_DELETED_DIRECTORY == op {
		return "Deleted"
	} else if utils.MODE_MOVED_FILE == op {
		return "Moved"
	} else if utils.MODE_RENAMED_FILE == op || utils.MODE_RENAMED_DIRECTORY == op {
		return "Renamed"
	} else if utils.MODE_REINSTATE_FILE == op || utils.MODE_REINSTATE_DIRECTORY == op {
		return "Reinstated"
	} else if utils.MODE_MODIFIED_CONTENTS == op || utils.MODE_MODIFIED_PERMISSIONS == op {
		return "Modified"
	} else {
		return "Unknown"
	}
}

func GetChunksHash(chunks string) []string {
	paths, err := base64.StdEncoding.DecodeString(chunks)
	if err != nil || len(paths) == 0 {
		return nil
	}
	num := len(paths) / (utils.HASH_BYTE_COUNT)
	var ret []string
	for i := 0; i < num; i++ {
		hashBytes := paths[i*utils.HASH_BYTE_COUNT : utils.HASH_BYTE_COUNT*(i+1)]
		chunkHash := fmt.Sprintf("%x", hashBytes)
		ret = append(ret, chunkHash)
	}
	return ret
}

func DoSaveObjectsToFile(objects map[string][]byte, root string, saveSharedToo, serverSide bool, user string) {
	topDirectory := root + "objects/"
	repoTree := root + "tree/"
	utils.Debugf("In DoSaveObjectsToFile. TopDir:%s, objects.len:%d, root:%s", topDirectory, len(objects), root)
	datFiles := make(map[string]map[string][]byte)
	for key, value := range objects {
		//dir := topDirectory
		pos := strings.Index(key, utils.DAT_SEPERATOR)
		toSave := true
		if pos > 0 {
			folderHash := key[0:pos]
			key = key[pos+1:]
			if saveSharedToo {
				toSave = false
				var shareFolder *utils.ShareFolder
				if serverSide {
					shareFolder = utils.GetShareFolderByRepoHashOnServer(user, repoTree, folderHash)
				} else {
					shareFolder = utils.GetShareFolderByRepoHash(repoTree, folderHash)
				}
				if shareFolder != nil {
					for u := range shareFolder.MemberKeys {
						utils.AddDatFile(datFiles, key, value, u)
					}
				}
			}
		}

		if toSave {
			utils.AddDatFile(datFiles, key, value, user)
		}
	}
	utils.SaveDatFiles(datFiles)
	utils.Debug("Leave DoSaveObjectsToFile")
}

//Returns a map of pub keys, which are in their raw format and not hex encoded.
func getAllPubKeys(users string) (map[string][]byte, error) {
	tokens := strings.Split(users, ",")
	missing := ""
	ret := make(map[string][]byte)
	for _, t := range tokens {
		if missing == "" {
			missing += t
		} else {
			missing += "," + t
		}
	}
	var e error
	if missing != "" {
		if response, err := utils.SendData("getPubkeys", "users", missing, nil); err == nil {
			for k, v := range response.Data {
				ret[k] = v
			}
		} else {
			e = err
		}
	}
	return ret, e
}

func GetFileExtension(file string) string {
	pos := strings.LastIndex(file, ".")
	if pos > 0 {
		return file[pos+1:]
	}
	return ""
}

func SaveRepoWithNameAndScan(name, localFolder string, encrypted, async bool) {
	config := utils.LoadConfig()
	m := make(map[string][]string)
	m["remote0"] = []string{"AnySync.net"}
	repo := createRepoFromRequest(m)
	repo.Name = name
	repo.Local = localFolder
	repo.EncryptionLevel = 0
	if encrypted {
		repo.EncryptionLevel = 1
	}
	tasks := CreateIndex("", name, &repo)
	utils.Debug("To save bin. apphome:", utils.GetAppHome(), "; user:", config.User)
	ExecuteTasks(tasks, true,  "")
	//os.Exit(0);
	sendReposToServer(tasks)
	repos := utils.GetAllRepositoryList(false)
	for _, r := range repos {
		if r.Name == name {
			if len(config.Locals) > 0 {
				config.Locals += utils.LOCALS_SEPARATOR1
			}
			config.Locals += fmt.Sprintf("%d%s%s", r.Index, utils.LOCALS_SEPARATOR2, localFolder)
			SaveConfig()
		}
	}

	utils.Debug("To rescan folders: ", localFolder)
	if async {
		go RescanFolders([]string{localFolder}, nil, true, 1, false)
	} else {
		RescanFolders([]string{localFolder}, nil, true, 1, false)
	}
}

func sendReposToServer(tasks []*utils.WriteTask) {
	utils.SendData("saverepos", "", "", tasks)
}

func createRepoFromRequest(values map[string][]string) utils.Repository {
	var repo utils.Repository
	existingRemotes := utils.GetRemotesIncludingTemps()
	userID := fmt.Sprintf("%d", utils.CurrentUser.ID)
	for key, val := range values {
		if strings.HasPrefix(key, "remote") {
			utils.Debug("RemoteName: ", key, "; val0: ", val[0])
			n := val[0]
			pos := strings.Index(n, " (")
			if pos > 0 {
				n = strings.TrimSpace(n[0:pos])
			}
			if n == "My Server" {
				m := make(map[string]string)
				m["bucket"] = "data"
				m["accessKeyID"] = userID
				p := utils.CreateNewRemote(existingRemotes, utils.REMOTE_TYPE_SERVER_NAME, utils.REMOTE_TYPE_SERVER, userID, m)
				p.Root = "data/objects/" + utils.IntStringToPath(userID)
				repo.Remote = append(repo.Remote, p)
			} else if n == "AnySync.net" {
				m := make(map[string]string)
				p := utils.CreateNewRemote(existingRemotes, utils.LoadAppParams().GetSelectedRemoteName(), utils.REMOTE_TYPE_OFFICIAL, userID, m)
				userPrefix := utils.CurrentUser.Prefix
				bucket := utils.CurrentUser.Bucket
				p.Root = bucket + "/" + userPrefix + "/"
				utils.Debug("Root is ", p.Root)
				repo.Remote = append(repo.Remote, p)
			} else {
				for _, r := range existingRemotes.Remote {
					if r.Name == n {
						if r.Type == "Dropbox" {
							r.Root = "Apps/" + utils.TOP_DIR
						} else { //dropbox already under anysyncnet directory
							r.Root = utils.TOP_DIR //top directory
						}
						if r.Type == utils.REMOTE_TYPE_S3 || r.Type == utils.REMOTE_TYPE_B2 {
							r.Root = r.Data["bucket"] + "/" + utils.TOP_DIR
						}
						repo.Remote = append(repo.Remote, r)
						break
					}

				}
			}

		}
	}

	return repo
}

func repoExists(name string) bool {
	repos := utils.GetRepositoryList()
	for _, r := range repos {
		if name == r.Name {
			return true
		}
	}
	return false
}

