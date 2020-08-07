// Copyright (c) 2020, Yanbin (Henry) Zheng <ybzheng@gmail.com>
// All rights reserved.
//
// Use of this source code is governed by a AGPLv3 license that can be
// found in the LICENSE file.
package client

import (
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/panjf2000/ants"
	_ "github.com/rclone/rclone/backend/all" // import all fs
	"github.com/rclone/rclone/cmd"
	"github.com/rclone/rclone/fs"
	"github.com/rclone/rclone/fs/config"
	"github.com/rclone/rclone/fs/filter"
	"github.com/rclone/rclone/fs/fserrors"
	"github.com/rclone/rclone/fs/log"
	"github.com/rclone/rclone/fs/operations"
	"github.com/rclone/rclone/fs/rc"
	"golang.org/x/net/context"
	"golang.org/x/sync/syncmap"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	utils "github.com/anysync/server/utils"
)

func CompressAndUploadPack(files []*utils.FileMeta, deletes  *syncmap.Map, repository * utils.Repository, objects *syncmap.Map ) ([]*utils.FileMeta, * utils.FileMeta, error) {
	var err error
	packFolder := utils.GetTopTmpFolder() + "/pack/" + repository.Name + "/"
	file := utils.GenerateRandomHash()
	packFile := packFolder + file
	if !utils.FileExists(packFolder) {
		utils.MkdirAll(packFolder)
	}
	utils.SendMsg( "Compress & encrypt pack file: " + file)
	utils.Debugf("TmpPackFile:%s, fileMetas.count: %d", packFile, len(files))
	isEncrypted := repository.EncryptionLevel == 1
	//DON'T remove it here defer utils.RemoveFile(packFile)
	var fileParts []*utils.FileMeta
	var packSize int64
	lastModified := uint32(0)
	var hashes []byte

	for _, fileMeta := range files{
		if lastModified == 0 {
			lastModified = fileMeta.GetLastModified()
		}
		if filePart, ps := appendToPackFile(packFile, fileMeta.P,  fileMeta.GetFileHash(), isEncrypted); filePart != nil {
			fileParts = append(fileParts, filePart)
			packSize += ps
		}
		hashes = append(hashes, utils.FromHex(fileMeta.GetFileHash()) ...)
	}

	if(err != nil){
		utils.Error("CompressAndUploadPack. Error is ", err)
		return nil, nil, err;
	}

	fileHash := utils.GetFileHash( packFile, repository.HashSuffix)
	filePart := utils.NewFileMeta(utils.FILE_META_TYPE_PACK, "", 0, packSize, fileHash)
	filePart.SetRepository(repository)
	filePart.SetLastModified( lastModified) //use the first part's lastModified value.
	filePart.B = encodeHashes(hashes)
	skipCompress := false;
	if(isEncrypted){skipCompress = true}
	err = CompressAndUpload(packFile, filePart, deletes, true, skipCompress, "", objects);
	return fileParts, filePart, err
}

type CompressJob struct{
	srcFile string
	fileMeta *utils.FileMeta
	deletes  *syncmap.Map
	skipEncrypt bool
	skipCompress bool
	ownerUserID string
	objects *syncmap.Map
}

var compressPool * ants.PoolWithFunc
var compressWait sync.WaitGroup

func createCompressPool() {
	compressPool, _ = ants.NewPoolWithFunc(50, func(i interface{}) {
		doCompressAndUpload(i)
		compressWait.Done()
	})
}

func CompressAndUpload(srcFile string, fileMeta *utils.FileMeta, deletes  *syncmap.Map, skipEncrypt bool, skipCompress bool, ownerUserID string ,
	objects *syncmap.Map) error {
	job := CompressJob{
		srcFile:srcFile,
		fileMeta:fileMeta,
		deletes:deletes,
		skipEncrypt:skipEncrypt,
		skipCompress: skipCompress,
		ownerUserID:ownerUserID,
		objects:objects,
	}
	if(compressPool == nil) {
		createCompressPool()
	}

	if(compressPool.Running() < compressPool.Cap()) {
		compressWait.Add(1)
		_ = compressPool.Invoke(job)
	}else{
		doCompressAndUpload(job)
	}

	return nil
}

func doCompressAndUpload(i interface{})  {
	j := i.(CompressJob)
	hashPath := utils.HashToPath(j.fileMeta.GetFileHash())
	finished := 0
	base := j.srcFile[0 : len(j.srcFile)-4]
	utils.Debug("Enter CompressAndUpload, remotes.size: ", len(j.fileMeta.GetRepository().Remote))
	encrypt := j.fileMeta.GetRepository().EncryptionLevel == 1
	if(j.skipEncrypt){ encrypt = false}
	for _, remote := range j.fileMeta.GetRepository().Remote {
		r := remote.Root;
		if(j.ownerUserID != ""){
			m := utils.GetUserInfo(j.ownerUserID);
			if m != nil {
				prefix :=  string(m["prefix"])
				ts := strings.Split(remote.Root, "/")
				r = ts[0] + "/" + prefix + "/";
			}
		}
		if(!strings.HasSuffix(r, "/")){
			r += "/"
		}
		path :=  r + "objects/" + hashPath + utils.EXT_OBJ
		utils.Debug("CompressAndUpload.path: ", path, "; remote.RemoteName: ", remote.Name, "; remote.T: ", remote.Type, "; remote.Root: ", remote.Root, ", encrytLevel:", encrypt)
		if compressed, e, _ := CloudCopyLz4File(j.srcFile,  &path, remote, j.fileMeta, base, encrypt, j.skipCompress); e == nil {
			p := CreatePath(j.fileMeta.GetRepository().EncryptionLevel, compressed, utils.META_PATH_STATE_NORMAL, remote.Name, path)
			if j.fileMeta.P != "" {
				j.fileMeta.P += utils.META_PATH_SEPERATOR + p
			} else {
				j.fileMeta.P = p
			}
			utils.Debug("fileMeta.P: ", j.fileMeta.P)
			finished++
		}else{//error occurred
			j.fileMeta.SetIncomplete( 2)
			return ;
		}
		//don't do the following: because it silently skip uploading and makes the file unable to be uploaded again.
		//else{
		//	err = e;
		//	p := fmt.Sprintf("%d%d%d%s", remote.EncryptionLevel,  compressed, utils.META_PATH_STATE_INCOMPLETE, path)
		//	if(fileMeta.P != ""){
		//		fileMeta.P += utils.META_PATH_SEPERATOR + p;
		//	}else{
		//		fileMeta.P = p;
		//	}
		//}
	}
	if finished == 0 {
		j.fileMeta.SetIncomplete( 2)
	} else if finished != len(j.fileMeta.GetRepository().Remote) {
		j.fileMeta.SetIncomplete( 1)
	} else if j.deletes != nil{ //no error
		if(utils.FileExists(base + utils.EXT_LZ4)) {
			j.deletes.Store(base+utils.EXT_LZ4, true)
		}
		if(utils.FileExists(base + utils.EXT_CZC)) {
			j.deletes.Store(base+utils.EXT_CZC, true)
		}
	}

	if j.fileMeta.GetIncomplete() == 0 {
		h := j.fileMeta.GetFileHash();
		if(len(j.ownerUserID) > 0){
			h = j.fileMeta.GetFolderHash() + utils.DAT_SEPERATOR + h;
		}
		if j.objects != nil {
			j.objects.Store(h, j.fileMeta)
		}
	}
}

func CloudCopyLz4File(srcFile string, destFile * string,  remote *utils.RemoteObject, fileMeta *utils.FileMeta, base string, toEncrypt bool, skipCompress bool  ) (int, error, bool) {
	newFile := base + utils.EXT_LZ4
	compressed := 0
	//defer utils.RemoveFile(newFile)
	if !utils.FileExists(newFile) {

		if(!skipCompress) {
			if err := utils.CompressLz4(srcFile, newFile); err != nil {
				return compressed, err, false
			} else {
				osize := utils.FileSize(srcFile)
				nsize := utils.FileSize(newFile)
				utils.Debugf("---osize:%d, nsize:%d", osize, nsize)
				if float64(nsize)/float64(osize) < 0.8 {
					compressed = 1
				} else { //if compression is not effective, use the original file
					skipCompress = true;
				}
			}
		}

		if(skipCompress){
			ioutil.WriteFile(newFile, []byte{}, utils.NEW_FILE_PERM) //change file size to zero
			//utils.Debugf("osize:%d, nsize:%d, newfile size is %d", osize,nsize, utils.FileSize(newFile))
			newFile = srcFile
		}
	} else {
		size := utils.FileSize(newFile)
		if size > 0 {
			compressed = 1
		} else {
			newFile = srcFile
		}
	}
	if toEncrypt {
		encFile := base + utils.EXT_CZC
		if !utils.FileExists(encFile) {
			//defer utils.RemoveFile(encFile)
			key, err := utils.GetFileEncKey(fileMeta.GetFileHash());
			if err != nil {
				return compressed, err, false
			}
			utils.Debugf("MKey:%x", key)

			if err := utils.EncryptFile(newFile, encFile, &key); err != nil {
				return compressed, err, false
			}
			utils.Debugf("Encrypted file size: %d, for file %s", utils.FileSize(encFile), encFile)
		}
		newFile = encFile
	}
	err, retry := CloudUploadFile(newFile, destFile, remote, fileMeta)
	return compressed, err, retry
}

func IsObjFileEncrypted(path string)bool{
	first := path[0]
	return 	first == '1';
}
func CreatePath(encryptionLevel uint32, compressed int, state int, remoteName, path string )string{
	return  fmt.Sprintf("%d%d%d%s:%s", encryptionLevel, compressed, state, remoteName, path)
}

func CloudCopyUnLz4File(fileMeta * utils.FileMeta, destFile string, skipDecrypt bool, fileHash string) error {
	cloudPath := fileMeta.P;
	tokens := strings.Split(cloudPath, utils.META_PATH_SEPERATOR)
	var err error
	retries := 3
	retry := false
	for i := 0; i < retries; i++ {
		for _, path := range tokens {
			first := path[0]
			state := path[2]
			compressed := path[1] == '1'
			if state != '0'+utils.META_PATH_STATE_NORMAL {
				continue
			}
			cpath := path[3:]
			if(cpath[0:1] == utils.LoadAppParams().GetSelectedRemoteName()){
				pos := strings.Index(cpath, utils.META_PATH_ID_SEPARATOR)
				if(pos > 0){
					cpath = cpath[0:pos];
				}
			}
			utils.Debug("~~~ To call doCloudCopy, src:", cpath, "; dest:", destFile)

			decrypt := first == '1';
			if(skipDecrypt) {decrypt = false}
			if err, retry = doCloudCopyUnLz4File(fileMeta, cpath, destFile, compressed, decrypt, fileHash); err == nil {
				return nil
			}else if(isNonRecoverableEror(err)){
				return err;
			}
		}
		if !retry {
			break
		} else {
			time.Sleep(20 * time.Second)
		}
	}

	return errors.New("CloudCopyUnLz4File. Not copied: " + destFile)
}

func isNonRecoverableEror(err error)bool{
	//2017-07-29T20:16:42.463-0400	ERROR	rpcrescan/Cloud.go:461	Error occurred in CloudCopy: invalid_access_token/.... src: 8f/7b/9f/191de46223e276401c4ef3d70e7417b204fceb48d112d68ef3.obj, dest: bc38bf8e552713c79ec8e9adb01c22693ea9e07265b131f65291e6ac
	text := fmt.Sprintf("%v", err);
	if(strings.Index(text, "invalid_access_token") >= 0){
		utils.Debug("error is not recoverable.")
		return true;
	}
	return false;
}

func decryptAndUnCompress(srcFile, fileHash, destFile string, toDecrypt, toDecompress bool, fileMetaK []string) error{
	if toDecrypt {
		var key [32]byte;
		found  := false;
		if fileMetaK != nil && len(fileMetaK) == 2 {//encrypted using share's owner's public key, the first token owner's userID.
			utils.Debug("FileMeta.K was encrypted using owner's pub key")
		}else if fileMetaK != nil && len(fileMetaK) == 1{
			if buf, err := base64.StdEncoding.DecodeString(fileMetaK[0]) ; err == nil {
				bs := buf[0:utils.HASH_BYTE_COUNT];
				if k, err := utils.GetShareKey(fmt.Sprintf("%x", bs)); err == nil {
					//utils.Debug("ShareKey: ", fmt.Sprintf("%x", k), "; bs: ", fmt.Sprintf("%x", bs))
					found = true;
					bs := utils.DecryptText(buf[utils.HASH_BYTE_COUNT:], &k)
					if (bs != nil) {
						copy(key[:], bs);
					}else{
						utils.Debug("Couldn't decrypt dat's text")
					}
				}
			}
		}
		if(!found) {
			k, err := utils.GetFileEncKey(fileHash);
			if err != nil {
				return err
			}
			key = k;
		}
		utils.Debugf("Decrypt. FileKey:%x, FileHash: %s", key, fileHash)
		encFile := utils.GetTopTmpFolder() + utils.GenerateRandomHash()
		defer utils.RemoveFile(encFile)
		if err := utils.DecryptFile(srcFile, encFile, &key); err != nil {
			utils.Debug("Failed to decrypt file: ", srcFile)
			return err
		}
		utils.Debug("Decrypt to ", encFile)
		srcFile = encFile
	}
	if toDecompress {
		if err := utils.DecompressLz4(srcFile, destFile); err != nil {
			return err
		}
		utils.Debug("Decompress to ", destFile)
	} else {
		if err := utils.Rename(srcFile, destFile); err != nil {
			return utils.CopyFile(srcFile, destFile)
		}
	}

	return nil;
}

func doCloudCopyUnLz4File(fileMeta * utils.FileMeta, cloudPath string, destFile string, compressed, encrypted bool, fileHash string) (error, bool) {
	var tmpFile string;
	objFile := utils.GetTopObjectsFolder() + utils.HashToPath(fileHash) + utils.EXT_OBJ;
	if(utils.FileExists(objFile)){
		tmpFile = objFile
	}else {
		tmpFile = utils.GetTopTmpFolder() + utils.GenerateRandomHash()
		utils.Debug("TmpFolder:", utils.GetTopTmpFolder()+"; tmpFile to copy to: ", tmpFile)
		if err, retry := CloudDownloadFile(cloudPath, tmpFile); err != nil {
			return err, retry
		}
		defer utils.RemoveFile(tmpFile)
		if !utils.FileExists(tmpFile) {
			utils.Warn("tmp file does not exist: ", tmpFile)
			return errors.New("file does not exist"), false
		}
	}
	decryptAndUnCompress(tmpFile, fileHash, destFile, encrypted && fileMeta.T != utils.FILE_META_TYPE_THUMBNAIL, compressed &&  fileMeta.T != utils.FILE_META_TYPE_THUMBNAIL, fileMeta.K)
	return nil, false
}

//if it's local copy (src and dest are local), copy directly; if dest is cloud, copy the file to the staging area.
// copy.go: fs.CopyDir(fdst, fsrc) -> sync.go: CopyDir
/**
Upload: srcFile is local, destFile can be local or cloud
@param srcFile source file RemoteName
*/
func CloudUploadFile(srcFile string,  destFile * string, remote * utils.RemoteObject, fileMeta *utils.FileMeta  ) (error, bool) {
	utils.Debugf("Enter cloud copy, src:%s, dest:%s", srcFile, *destFile)
	if(remote != nil){utils.Debug("In CloudCopyFile, remote.RemoteName:", remote.Name, "; Remote.T:", remote.Type)}
	isLocal := remote != nil && remote.Type == utils.REMOTE_TYPE_LOCAL_NFS
	if isLocal {
		df := remote.Value + "/" + (*destFile);
		utils.Debugf("isLocal:%v, CloudCopyFile src: %s, destFile: %s", isLocal, srcFile, *destFile);
		if err := utils.CopyFile(srcFile, df); err != nil {
			utils.Errorf("Error occurred in CloudCopy: %v. src: %s, dest: %s", err, srcFile, *destFile)
			return err, false //CopyFile(srcFile,destFile);
		}
	}else if(/*ownerUserID != "" ||*/ fileMeta.GetNoStaging()){
		srcDir, srcFileName := GetDirAndFile(srcFile, true)
		destFileName := utils.GetLastPathComponent(*destFile)
		tokens:=strings.Split(*destFile, "/")
		size := len(tokens)
		var  dest, destFull string;
		//if(fileMeta.noStaging){
		cp := utils.DecodePath(fileMeta.P)
		dest = cp.RemoteName + ":" + cp.Path
		pos:= strings.LastIndex(dest, "/")
		dest = dest[0:pos]
		utils.Debug("remote.name:" , remote.Name , "; root:", remote.Root, ";dest: ", dest, "; destFileName:", destFileName, "; srcDir: ", srcDir, "; srcFileName: ", srcFileName)
		args := []string{srcDir, dest}
		fsrc, fdst := cmd.NewFsSrcDst(args)
		if err := operations.CopyFile(context.Background(), fdst, fsrc, destFileName, srcFileName); err != nil {
			utils.Errorf("Error occurred in CloudCopy: %v. src: %s, dest: %s", err, srcFileName, destFileName)
			if err := operations.CopyFile(context.Background(), fdst, fsrc, destFileName, srcFileName); err != nil {
				return err, false;
			}
		}else{
			if(remote.Name == utils.LoadAppParams().GetSelectedRemoteName()) {
				* destFile = fdst.Root() + tokens[size-1];
			}else {
				* destFile = destFull;
			}
			//utils.Debug("destFile: ", *destFile)
			//fileMeta.P = destFull;
		}

	} else {
		dfile := utils.GetStagingFolder() + fileMeta.GetRepository().Hash + "/" +  "/objects/" + utils.HashToPath(fileMeta.GetFileHash()) + utils.EXT_OBJ
		if(!utils.FileExists(dfile)) {
			dir := filepath.Dir(dfile);
			//Debugf("dest:%s, fileName:%s\n", dest, fileName)
			if(!utils.FileExists(dir)){
				utils.MkdirAll(dir);
			}
			utils.WriteString(dfile, srcFile)
			utils.Debug("utils.Renamed src: ", srcFile, " ; to ", dfile)
		}
		if fileMeta.GetLastModified() != 0 {
			utils.SetFileModTime(dfile, fileMeta.GetLastModified()) //set file mod time, so that future copy of the same file will be skipped by rclone (which check mod time and filesize to see if file has been uploaded to the cloud)
			utils.Debug("Set file mod time. file: ", dfile, "; modtime: ", fileMeta.GetLastModified())
		}
	}
	fileMeta.C = utils.FileSize(srcFile)
	return nil, false
}

//Download: destFile is local, srcFile can be local or cloud
func CloudDownloadFile(srcFile, destFile string) (error, bool) {
	//destFile = "/tmp/obj.1"
	utils.Debug("Enter CloudDownloadFile, src:", srcFile, ";dest:", destFile)
	isLocal := false;
	var remotes utils.Repository;
	var remote *utils.RemoteObject; var path string;
	//if(strings.HasPrefix(srcFile, utils.REMOTE_TYPE_SERVER_NAME + ":")){
	//	isServer = true;
	//	utils.Debug("====== It's server")
	//}else {
		remotes = utils.GetRemotes();
		remote, path = findRemote(remotes, srcFile);
		if (remote != nil) {
			srcFile = path;
		}
		isLocal = remote != nil && remote.Type == utils.REMOTE_TYPE_LOCAL_NFS
	//}
	//debug.PrintStack();
	if isLocal {
		srcFile = remote.Value + "/" + srcFile;
		utils.Debugf("isLocal:%v, CloudCopyFile src: %s, destFile: %s", isLocal, srcFile, destFile);
		if err := utils.CopyFile(srcFile, destFile); err != nil {
			utils.Errorf("Error occurred in CloudCopy: %v. src: %s, dest: %s", err, srcFile, destFile)
			return err, false //CopyFile(srcFile,destFile);
		}
	} else {
		if(remote != nil) {
			if(remote.Type == utils.REMOTE_TYPE_LOCAL_NFS){
				srcFile = remote.Value + "/" + srcFile;
			}else {
				srcFile = remote.Name + ":" + srcFile;
			}
		}
		destFile = filepath.Clean(destFile)
		//fs.Config.Filter, _ = fs.NewFilter() //otherwise it cause annoying message in cmd.go::newFsSrc - Can't limit to single files when using filters
		srcDir, srcFileName := GetDirAndFile(srcFile, isLocal)
		destDir, destFileName := GetDirAndFile(destFile, true)
		utils.Debug("srcDir: ", srcDir, "; destDir: ", destDir, "; destFileFullName: ", destFile)
		utils.Debug("srcFile: ", srcFileName, "; destFile: ", destFileName)
		args := []string{srcDir, destDir}
		fsrc, fdst := NewFsSrcDst(args)
		if fsrc == nil || fdst == nil {
			return errors.New("cannot create fs"), false
		}
		utils.Debug("srcFileName:", srcFileName, "; srcDir: ", srcDir, "; destFileName: ", destFileName, "; destDir:", destDir)
		//if err := fs.CopyFile(fdst, fsrc, destFileName, srcFileName); err != nil {
		if err, retry := DoCloudCopyFile(fdst, fsrc, destFileName, srcFileName); err != nil {
			return err, retry
		} else {
			utils.Debug("=========== Successfully copied file to: ", destFile)
		}
	}
	return nil, false
}

func GetDirAndFile(file string, isLocal bool) (string, string) {
	if isLocal {
		return utils.RemoveLastPathComponent(file), utils.GetLastPathComponent(file)
	} else {
		return GetFirstPathComponent(file)
	}
}

//rReturns for "Dropbox:/tmp/test/p.txt" returns "Dropbox:/"
func GetFirstPathComponent(path string) (string, string) {
	pos := strings.Index(path, "/")
	if pos <= 0 {
		return path, ""
	} else {
		return path[:pos+1], path[pos+1:]
	}
}

//copy to a tmp file first, then rename the tmp file to dest file.
func CopyObjectFromServerTo( destFile string, fileHash string) error {
	utils.SendToLocal(utils.MSG_PREFIX + "To copy cloud file to " + destFile)
	defer utils.SendToLocal(utils.MSG_PREFIX + "Copied cloud file to " + destFile)
	subPath := utils.HashToPath(fileHash);
	tmpFile := utils.GetTopTmpFolder() + utils.GenerateRandomHash()
	obj := utils.GetTopObjectsFolder() + subPath + utils.EXT_OBJ
	utils.Debug("In CopyObjectFromServerTo, objFile:", obj, "; dest:", destFile)
	if !utils.FileExists(obj) {
		utils.Debugf("CopyObjectFromServerTo. To call GetCloudFile, tmpFile:%s\n", tmpFile)
		if err:=GetCloudFile(obj, fileHash,  tmpFile);err != nil{
			return err;
		}else{
			utils.RemoveFile(destFile)
			dir := filepath.Dir(destFile);
			if(!utils.FileExists(dir)){
				utils.MkdirAll(dir);
			}
			err = utils.Rename(tmpFile, destFile);
			if(err == nil){
				utils.Debug("Successfully copy file from cloud to ", destFile)
			}else{
				utils.Warn("Couldn't copy file to ", destFile)
			}
		}
	} else {
		return utils.CopyFile(obj, destFile)
		//utils.RemoveFile(destFile)
		//return utils.Rename(tmpFile, destFile);
	}
	return nil
}

func CopyObjectFromServer(fileHash string) error {
	subPath := utils.HashToPath(fileHash);
	utils.Debugf("Enter copyObjectFrom server: %s\n", subPath)
	dest := utils.GetTopObjectsFolder() + subPath + utils.EXT_OBJ
	return CopyObjectFromServerTo(dest, fileHash)
}

var _fsMap = new(syncmap.Map);// cmap.New() // cmap.ConcurrentMap;

func getFs(k string) fs.Fs {
	if o, ok := _fsMap.Load(k); ok {
		return o.(fs.Fs) // fs.Fs(o);
	}
	return nil
}

func NewFsSrcDst(args []string) (fs.Fs, fs.Fs) {
	var fsrc, fdst fs.Fs
	utils.Debug("NewFS. src:", args[0], "; dest:", args[1])

	if fsrc == nil || fdst == nil {
		utils.Debugf("Create a new fs for src or dest. args:%v", args)
		fsrc, fdst = cmd.NewFsSrcDst(args)
	}

	if fsrc != nil && fdst != nil {
		_fsMap.Store(args[0], fsrc)
		_fsMap.Store(args[1], fdst)
	}
	return fsrc, fdst
}

//====================================================================================================
//from rclone:

func RcloneInit() {
	os.Setenv("RCLONE_STATS", "2s")
	log.InitLogging()
	conf := utils.LoadConfig();
	SetRateLimit(conf.RateLimit) //avoid calling utils.LoadConfig, because it tries to use GRPC to get remotes info, but at this time the main server is not started yet.
	if(conf.ThreadCount > 0) {
		fs.Config.Transfers = conf.ThreadCount;
	}
	fs.Config.AskPassword = false
	config.LoadConfig() // startTokenBucket() and startTokenTicker() are called inside fs.LoadConfig().
	fs.Config.LogLevel = fs.LogLevelDebug
	filter.Active.Opt.DeleteExcluded = false;
	filter.Active.Opt.MinSize = -1
	filter.Active.Opt.MaxSize = -1 //100000000;
	fs.Config.LowLevelRetries = 1
	//fs.Config.DataRateUnit = "bits"
	fs.Config.InsecureSkipVerify = true //don't check SSL cert.

	//fs.Config.Transfers = 1
	fs.Config.IgnoreExisting = true   //skip uploading file if remote file already exists.
}

var cloudMutex = &sync.Mutex{}

//copy from utils.CopyFile() func in operations.go. utils.CopyFile() has retries in it so it must be modified.
func DoCloudCopyFile(fdst fs.Fs, fsrc fs.Fs, dstFileName string, srcFileName string) (err error, ret bool) {
	cloudMutex.Lock()
	defer cloudMutex.Unlock()

	if err := operations.CopyFile(context.Background(), fdst, fsrc, dstFileName, srcFileName); err != nil {
		retry := fserrors.IsRetryError(err) || fserrors.ShouldRetry(err)
		utils.Debug("fsrc:", fsrc, "; fdst: ", fdst)
		utils.Errorf("Error occurred in CloudCopy, retriable: %v. : %v. src: %s, dest: %s", retry, err, srcFileName, dstFileName)
		return err, retry
	} else {
		return nil, false
	}
}

func SaveConfig(){
	if(utils.CurrentConfig == nil){return}
	SaveConfigFile(utils.CurrentConfig, utils.GetConfigFile());
}

func SaveConfigFile(config * utils.Config, file string){
	skip := utils.SaveConfigFile(config, file);
	if(!skip) {
		ChangeRateLimit(config);
	}
	if(config.ThreadCount > 0) {
		fs.Config.Transfers = config.ThreadCount;
	}
}


func  SetRateLimit(RateLimit int){
	call := rc.Calls.Get("core/bwlimit")
	val := fmt.Sprintf("%dM", RateLimit)
	in := rc.Params{
		"rate": val,
	}
	if _, err := call.Fn(context.Background(), in); err != nil{
		utils.Warn("Failed to set rate limit.")
	}
}

func  ChangeRateLimit(config * utils.Config){
	SetRateLimit(int(config.RateLimit ));
}

func findRemote(repo utils.Repository, srcFile string ) (*utils.RemoteObject,string){
	pos := strings.Index(srcFile, ":")
	if(pos < 0){ return nil, "";}
	name := srcFile[0:pos];
	//utils.Debug("findRemote. r name is ", name, "; without rname, path is ", srcFile[pos+1:], "; Remote.length: ", len(repo.Remote));
	for _, r := range repo.Remote {
		//utils.Debug("r.name: ", r.RemoteName)
		if(r.Name == name){
			re := utils.RemoteObject{};
			re.Name = r.Name;
			re.Type = r.Type;
			re.Value = r.Value;
			//utils.Debug("Found Remote, name is ", re.RemoteName , " ; value is ", re.GetValue())
			return & re, srcFile[pos+1:];
		}
	}
	utils.Debug("No remote was found.")
	return nil,"";
}

//srcPath: ":objects/1d/59/35/9433555bd2d1fd65f98a8d0ce9ad0d53c468dbb1df70dcfa68.obj"
//or .AnySync/1170459/tree/f5/e9/d7/8459319ab349f90b01441263a5acb7ea6387837330b5b77df6.bin
func GetHashFromPath(srcPath string )string{
	pos2 := strings.LastIndex(srcPath, ".")
	count := 0
	for i := pos2 ; i >= 0; i-- {
		if(srcPath[i] == '/'){
			count ++;
			if(count == 4){
				text := srcPath[i:pos2]
				text = strings.Replace(text, "/", "", -1)
				//utils.Debug("srcPath:", srcPath, "; ret: ", text)
				return text;
			}
		}
	}
	return "";
}
