// Copyright (c) 2020, Yanbin (Henry) Zheng <ybzheng@gmail.com>
// All rights reserved.
//
// Use of this source code is governed by a AGPLv3 license that can be
// found in the LICENSE file.
package client

import (
	"bytes"
	"database/sql"
	"errors"
	"fmt"
	"github.com/panjf2000/ants"
	"github.com/rclone/rclone/cmd"
	"github.com/rclone/rclone/fs"
	"github.com/rclone/rclone/fs/accounting"
	"github.com/rclone/rclone/fs/filter"
	"github.com/rclone/rclone/fs/filter/filterflags"
	"github.com/rclone/rclone/fs/operations"
	fsync "github.com/rclone/rclone/fs/sync"
	"golang.org/x/net/context"
	"golang.org/x/sync/syncmap"
	"io/ioutil"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
	utils "github.com/anysync/server/utils"
)

type Rescan struct {
	recursively     bool
	ignoreDirectory bool
	ignoreDeletes   bool
	traversedDirs   map[string]bool
	modifiedFolders []*utils.ModifiedFolderExt
	deletedFiles    map[string][]*DeletedRowData
	fileHashMap            map[string]*utils.RealFileInfo
	changeCount            int
	incomplete             bool
	currentRepository      *utils.Repository
	symFolders             []*utils.RealFileInfo
	isProcessingSymFolders bool
	isMaxReached           bool
	shareState             int32
	owner                    string
	keepCorruptedFile bool
	filter   *FilterEx
}

func NewRescan() *Rescan {
	rescan := new(Rescan)
	rescan.recursively = true
	rescan.traversedDirs = make(map[string]bool)
	rescan.deletedFiles = make(map[string][]*DeletedRowData)
	rescan.fileHashMap = make(map[string]*utils.RealFileInfo)
	rescan.changeCount = 0
	rescan.incomplete = false
	return rescan
}

func scanStart() bool{
	state := SyncState.GetValue();
	if(state == SYNC_STATE_SYNCING || state == SYNC_STATE_RESTORING){
		utils.Debug("Scan was not started.")
		return false
	}
	SyncState.SetValue(SYNC_STATE_SYNCING)
	utils.SendToLocal("scanStart")
	return true
}

func scanDone(errMsg string){
	SyncState.SetValue(SYNC_STATE_SYNCED)
	if errMsg == "" {
		utils.SendToLocal("scanDone")
	}else{
		utils.SendToLocal("done: " + errMsg)
	}
}
func isScanning() bool{
	state := SyncState.GetValue();
	return state == SYNC_STATE_SYNCING || state == SYNC_STATE_RESTORING
}

func StartRescan(f func([]*utils.ModifiedFolderExt) error) bool{
	if(utils.CurrentUser == nil){
		utils.Info("Not authenticated.")
		return false
	}
	now := uint32(time.Now().Unix());
	if(now >= (utils.CurrentUser.Expiry + 86400 * 2) ){
		utils.SendToLocal(utils.MSG_PREFIX + "Account already expired.")
		utils.Info("Account already expired.")
		return false
	}
	var errMsg string
	if !scanStart() {
		return false
	}
	utils.Debug("Enter StartRescan.")

	repos, myShares, shared := repoToFolderEx()
	//handle shares first and then regular repos.
	if(myShares != nil && len(myShares) > 0) {
		_, errMsg = rescanFolderEx(myShares, "", f, 1, utils.REPO_SHARE_STATE_OWNER, false, false)
	}
	if(shared != nil && len(shared) > 0){
		for owner, shares := range shared{
			_,errMsg = rescanFolderEx(shares, owner, f, 1, utils.REPO_SHARE_STATE_SHARE, false, false)
		}
	}

	if(len(repos) > 0) {
		_, errMsg = rescanFolderEx(repos,  "", f, 1, utils.REPO_SHARE_STATE_ALL, false, false)
	}
	scanDone(errMsg)
	return true
}

func RescanFolders(folders []string, f func([]*utils.ModifiedFolderExt) error, isNewRepo bool, contactServerEvenNoChange int, nonRecursiveScan bool) bool {
	if !scanStart() {
		return false
	}
	var errMsg string
	utils.Debug("Enter RescanFolders. folders:", folders)
	folderEx, myShares, shared := foldersToFolderEx(folders, isNewRepo)
	if(myShares != nil && len(myShares) > 0) {
		_, errMsg = rescanFolderEx(myShares, "", f, contactServerEvenNoChange, utils.REPO_SHARE_STATE_OWNER, nonRecursiveScan, false)
	}
	if(shared != nil && len(shared) > 0) {
		for owner, shares := range shared{
			_, errMsg=rescanFolderEx(shares, owner, f, contactServerEvenNoChange, utils.REPO_SHARE_STATE_SHARE, nonRecursiveScan, false)
		}
	}
	if(len(folderEx) > 0) {
		_, errMsg=rescanFolderEx(folderEx,  "", f, contactServerEvenNoChange, utils.REPO_SHARE_STATE_ALL, nonRecursiveScan, false)
	}
	scanDone(errMsg)
	return true
}

type SyncStateData struct {
	mu  sync.Mutex
	value   int
}
const (
	SYNC_STATE_INITIAL = -1
	SYNC_STATE_SYNCED  = 0
	SYNC_STATE_SYNCING = 1
	SYNC_STATE_RESTORING = 2
)

var SyncState  = SyncStateData{value : SYNC_STATE_INITIAL,}

func (s * SyncStateData) SetValue(v int){
	s.mu.Lock()
	defer s.mu.Unlock()
	s.value = v
}
func (s  SyncStateData) GetValue()int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.value
}

var SyncingRepos string
var scanMutex = &sync.Mutex{}
var toRescan bool
/**
@param contactServerEvenNoChange 0: don't contact server if no change ; 1: contact server even if no change; 2: don't contact server anyway
 */
func rescanFolderEx(folders []FolderEx, owner string,  f func([]*utils.ModifiedFolderExt) error, contactServerEvenNoChange int, shareState int32, nonRecursiveScan bool, keepCorruptedFile bool) (*Rescan, string) {
	if(utils.CurrentUser == nil){
		return nil, "";
	}
	cloudStorage := utils.CountTotalSize(false);
	totalInGB, _ := utils.ToInt64(cloudStorage)
	if utils.CurrentUser.Quota > 0 && totalInGB > int64(utils.CurrentUser.Quota) * utils.GB {
		utils.Info("Exceeded quota: ", utils.CurrentUser.Quota , "GB; Used ", totalInGB/utils.GB, "GB")
		return nil, ""
	}

	scanMutex.Lock()
	ClearScan()
	deletes := new(syncmap.Map) //store files to be deletes
	var errMsg string
	toRescan = false;
	defer cleanUp(deletes, errMsg)

	config := utils.LoadConfig()
	utils.Info("To rescan folder: ", folders, "; owner:", owner)
	var headers map[string]string
	var rpcSyncRet int32
	var localDir string
	if config.Mode == utils.CONFIG_MODE_PLACEHOLDER {
		rescan := NewRescan()
		errMsg, rpcSyncRet = rescan.rpcSync(headers,  true, f, deletes, 0)
	} else {
		for {
			utils.Debug("To create new rescan obj")
			rescan := NewRescan()
			rescan.keepCorruptedFile = keepCorruptedFile
			rescan.recursively = !nonRecursiveScan;
			if(shareState != utils.REPO_SHARE_STATE_ALL){
				rescan.recursively = false;
				if(shareState == utils.REPO_SHARE_STATE_SHARE) {
					rescan.ignoreDirectory = true;
				}
			}
			for _, folder := range folders {
				rescan.currentRepository = folder.repo // repo.Name;
				rescan.shareState = shareState;
				localDir = rescan.currentRepository.Local
				rescan.owner = owner;
				utils.Debug("StartRescan dir: ", folder.absPath)
				utils.SendToLocal(utils.MSG_PREFIX + "Scan directory: .../" + utils.Basename2(folder.absPath))
				folderHash := ""
				if(shareState != utils.REPO_SHARE_STATE_ALL){
					folderHash = folder.repo.Hash;
				}
				err := rescan.startRescan(folder.absPath, folder.files, folder.relativePath,  true, folderHash, folder.hashSuffix)
				//err := rescan.startRescan(absPath, "Root/"+repo.Name, utils.HEAD_TEXT, true);
				if err != nil || rescan.incomplete {
					break
				}
				utils.Debug("To loop thru symFolders, size: ", len(rescan.symFolders))
				rescan.traversedDirs = nil
				rescan.traversedDirs = make(map[string]bool)
				rescan.isProcessingSymFolders = true
				for _, symFolder := range rescan.symFolders {
					utils.Debug("To scan symFolder: ", symFolder.AbsPath, "; relativePath: ", symFolder.RelativePath, "; parentFolderHash:", symFolder.ParentHash)
					err := rescan.startRescan(symFolder.AbsPath, folder.files, symFolder.RelativePath, true, folderHash, folder.hashSuffix)
					if err != nil || rescan.incomplete {
						break
					}
				}
			}
			utils.Debug("To call fixRenaming")
			rescan.fixRenaming()
			rescan.clear()

			utils.Debug("ModifiedFolders.size: ", len(rescan.modifiedFolders), "; contactServerEvenNoChange: ", contactServerEvenNoChange)
			if(contactServerEvenNoChange == 2) {
				//dont contact server
				return rescan, "";
			}
			n := rescan.countChanges()
			utils.SendToLocal(utils.MSG_PREFIX + fmt.Sprintf( "Total changes: %d", n))
			if(n == 0 && contactServerEvenNoChange != 1){
				return  rescan, "";
			}
			if f != nil {
				errMsg, rpcSyncRet = rescan.rpcSync(headers,  true, f, deletes, n)
			} else {
				if contactServerEvenNoChange == 1 || len(rescan.modifiedFolders) > 0 {
					utils.Debug("To call rpcSync...ShareState: ", shareState)
					errMsg, rpcSyncRet = rescan.rpcSync(headers, true, f, deletes, n)
					utils.Debug("rpcSyncRet:", rpcSyncRet)
					if rpcSyncRet == 0 {
						toRescan = true;
					}
				}
			}
			if !rescan.incomplete  || rpcSyncRet == 2 {
				break
			}
			gUploadedBytes += gCurrentUploadedBytes;
			gCurrentUploadedBytes = 0;
			utils.Debug("Start over scanning ... gUploadedBytes: ", gUploadedBytes)
			rescan = nil
		}
	}
	if rpcSyncRet == 2 {
		utils.Info("Too many changes on server, to restore all from complete meta data set. Local directory:", localDir)
		RestoreCurrent(config.Mode, localDir)
		return nil, ""
	}
	if(contactServerEvenNoChange == 2) {
		return nil, "";
	}
	if errMsg != "" {
		SyncingRepos = toRepos(folders)
		errMsg = SyncingRepos + errMsg
		utils.SendToLocal(utils.MSG_PREFIX+errMsg)
	}
	return nil, errMsg;
}

func RestoreCurrent(mode int, restoreDirectory string ) {
	//utils.CloseListener(
	utils.AskRestore = false
	utils.SendToLocal(utils.MSG_PREFIX + "To restore files to " + restoreDirectory + " ...")

	utils.ResetCallback =  func() {
		//Invoked after resetgetall downloaded and created tree and objects directories.\
		fmt.Println("Meta data downloaded2.")
		config := utils.LoadConfig()
		config.Mode = mode
		SaveConfig()
		if mode == utils.CONFIG_MODE_PLACEHOLDER {
			return
		}
		setLocalPaths(config, []string{restoreDirectory})

		utils.SendToLocal("torestore")
		RestoreAll()
		utils.SendToLocal("restoreDone")
		utils.SendToLocal("reloadTree")
		fmt.Println("Complete successfully.")
	};
	utils.CallResetGetAll("");
}

var lastScanTime int64
func StartRescanTimer(){
	for {
		time.Sleep( 1*time.Minute);
		config := utils.LoadConfig();
		if(config.Mode == utils.CONFIG_MODE_PLACEHOLDER){
			break;
		}
		t2 := time.Now().Unix();
		state := SyncState.GetValue()
		if state != SYNC_STATE_SYNCING && (t2 - lastScanTime) > int64(60 * config.ScanInterval)  {
			changes := checkChanges("",false)
			var recursiveFolders, folders []string
			changes.Range(func(k, v interface{}) bool {
				b := v.(bool)
				folder := k.(string)
				if(b){
					recursiveFolders = append(recursiveFolders, folder)
				}else {
					folders = append(folders, folder)
				}
				return true
			})
			utils.Debug("checkChanges returned. len(recursiveFolders):", len(recursiveFolders), "; len(folders):", len(folders))
			if len(recursiveFolders) > 0 {
				utils.Info("Recursive Rescan after", config.ScanInterval, " minutes of no-scan for folders:", recursiveFolders )
				go RescanFolders(recursiveFolders, nil, false, 1, false)
			}
			if len(folders) > 0 {
				utils.Info("Rescan after", config.ScanInterval, " minutes of no-scan for forders:", folders )
				go RescanFolders(folders, nil, false, 1, true)
			}
			if (t2 - lastScanTime) > int64(60 * config.ScanInterval * 3) &&  len(folders) == 0 && len(recursiveFolders) == 0 {
				go StartRescan(nil)
			}

		}
	}
}

func cleanUp(deletes *syncmap.Map, errMsg string) {
	scanMutex.Unlock()
	utils.SendToLocal("done: " + errMsg)
	deleteFiles(deletes)
	go utils.RemoveEmptySubfolders(utils.GetTopObjectsFolder())

	utils.Info("Return from rescanFolderEx")
	ClearScan()
	if(toRescan){
		utils.Debug("In cleanup, to call StartRescan...")
		StartRescan(nil)
	}
}

func deleteFiles(deletes *syncmap.Map) {
	deletes.Range(func(k, v interface{}) bool {
		_, ok := v.(bool)
		if ok {
			fname := k.(string)
			utils.Debug("---Delete folder: ", fname)
			_ = utils.RemoveAllFiles(fname)
		}
		return true
	})
}

func createFolders() {
	var folders = []string{utils.GetTasksFolder(), utils.GetLogsFolder(), utils.GetTopTmpFolder(), utils.GetPacksFolder(), utils.GetDataFolder()}
	for _, folder := range folders {
		if !utils.FileExists(folder) {
			_=utils.MkdirAll(folder)
		}
	}
}

func (this *Rescan) startRescan(srcAbsPath string, files [] string, currentRelativePath string,  updateMeta bool, folderHash, hashSuffix string) error {
	srcAbsPath = filepath.Clean(srcAbsPath)
	if this.traversedDirs != nil {
		this.traversedDirs[srcAbsPath] = true
	}
	info, err := os.Lstat(srcAbsPath)
	if err != nil  {
		return err
	}
	isDir := info.IsDir();
	var fileNames []*utils.RealFileInfo
	if(isDir && len(files) == 0) {
		dir, err := os.Open(srcAbsPath)
		if err != nil {
			return err
		}
		defer dir.Close()
		fis, err := dir.Readdir(-1)
		if err != nil { //may be because there is no privilege
			return err
		}
		if (len(folderHash) == 0) {
			folderHash = utils.GetFolderPathHash(currentRelativePath)
		}
		fis = removeSelectedFolders(currentRelativePath, fis)
		fileNames = this.fixSymlinks(fis, currentRelativePath, srcAbsPath, folderHash)
	}else{
		this.recursively = false;
		//this.ignoreDeletes = true;
		if(!isDir) {
			if rfi, err := utils.GetRealFileInfo(srcAbsPath); err == nil {
				fileNames = append(fileNames, rfi)
			} else {
				return err;
			}
		}else if(len(files) > 0){
			for _, file := range files{
				rfi, _ := utils.GetRealFileInfo(srcAbsPath + "/" + file)
				rfi.IsDir = false;
				rfi.IsFile = true;
				rfi.Name = file;
				fileNames = append(fileNames, rfi)
			}
		}
	}

	mfolder := utils.NewModifiedFolderExt()
	mfolder.Repository = this.currentRepository
	mfolder.RepoHash = this.currentRepository.Hash;
	mfolder.FolderHash = folderHash
	mfolder.ParentHash = utils.GetFolderPathHash(filepath.Dir(currentRelativePath))
	mfolder.RelativePath = currentRelativePath
	mfolder.AbsPath = srcAbsPath;
	this.rescanDirectory(srcAbsPath, currentRelativePath, fileNames, mfolder,  updateMeta, hashSuffix)
	return nil
}

func (this *Rescan) rescanDirectory(directoryAbsPath string, currentRelativePath string, fileNames []*utils.RealFileInfo, mfolder *utils.ModifiedFolderExt,  updateMeta bool, hashSuffix string) bool {
	if mfolder.FolderHash == ""{
		utils.Error("Empty folderhash, directoryAbsPath:", directoryAbsPath, "; relativePath:", currentRelativePath)
		return false
	}
	utils.SendToLocal(utils.MSG_PREFIX + "Scan directory: .../" + utils.Basename2(directoryAbsPath))

	subPath := utils.HashToPath(mfolder.FolderHash)
	path := utils.GetTopTreeFolder() + subPath
	pathBin := path + ".bin"
	binRowMap := make(map[string]*utils.IndexBinRow) //Map file Name key to IndexBinRow object
	deletedItemMap := make(map[string]*utils.IndexBinRow)
	readIndexBinData(pathBin, binRowMap, deletedItemMap)
	newItemMap := make(map[string]bool)
	newRowIndex := uint32(utils.FileSize(pathBin) / utils.FILE_INFO_BYTE_COUNT)
	if newRowIndex == 0 {
		newRowIndex = 1
	}
	var dirs []*utils.RealFileInfo
	for _, fileInfo := range fileNames {
		if !this.handleFile(fileInfo, mfolder, currentRelativePath, &newRowIndex, pathBin, updateMeta,
			binRowMap, newItemMap, deletedItemMap, &dirs, hashSuffix) {
			this.isMaxReached = true
			break
		}
	}
	config := utils.LoadConfig()
	var db * sql.DB
	if len(binRowMap) > 0 && config.Mode != utils.CONFIG_MODE_NEW_ONLY && !this.ignoreDeletes {
		hasSelectedFolder := config.HasSelectedFolder()

		for _, item := range binRowMap {
			if(hasSelectedFolder && utils.IsFileModeDirectory(item.FileMode)){
				folder := currentRelativePath[len(utils.ROOT_NODE) + 1 : ]
				key := folder + "/" + item.Name
				if config.IsSelectedFolder(key) {
					continue
				}
			}
			if utils.IsFileModeDeleted(item.FileMode) {
				continue
			}
			hash := item.ToHashString()
			if db == nil {
				db = utils.NewDownloadDb()
			}
			if _, b := utils.DbGetValue(mfolder.FolderHash + "|" + item.ToHashString()); b {
				//file not downloaded yet
				continue
			}
			if utils.IsFileModeRegularFile(item.FileMode) {
				if newRow, ok := AddRow(mfolder, item.Index, utils.MODE_DELETED_FILE, nil, item.Name, false, this); ok {
					d := NewDeletedRowData(item.Index, pathBin, mfolder.FolderHash, item.Name, newRow);
					d.fileNameKey = item.FileNameKey
					if t, f := this.deletedFiles[hash]; f {
						t = append(t, d);
						this.deletedFiles[hash] = t;
					} else {
						this.deletedFiles[hash] = []*DeletedRowData{d}
					}
				}
			} else if utils.IsFileModeDirectory(item.FileMode) && !this.ignoreDirectory {
				relPath := currentRelativePath + "/" + (item.Name)
				dirNameHash := utils.GetFolderPathHash(relPath)
				fileNameKey := item.FileNameKey;
				utils.Debug("deleted dir. relpath: ", relPath, "; fileNameKey: ", fileNameKey)
				newRow := updateRowAt(pathBin, item.Index, fileNameKey, nil,  &dirNameHash, item.FileMode, utils.MODE_DELETED_DIRECTORY)
				newModRow,_ := AddRow(mfolder, item.Index, utils.MODE_DELETED_DIRECTORY, &newRow, item.Name, true, this)
				if this.recursively {
					processed := make(map[string]bool)
					this.recursivelyDeleteSubs(utils.GetFolderPathHash(relPath), processed)
				}else{
					d := NewDeletedRowData(item.Index, pathBin, mfolder.FolderHash, item.Name, newModRow);
					d.hash = dirNameHash;
					d.fileNameKey = item.FileNameKey
					this.deletedFiles[hash] = []*DeletedRowData{d};
				}
			}
		}
	}
	utils.CloseDb(db)

	if len(mfolder.Rows) > 0 {
		if folder := containsFolderExt(this.modifiedFolders, mfolder.FolderHash); folder != nil {
			for key, val := range mfolder.Rows {
				folder.Rows[key] = val
			}
		} else {
			this.modifiedFolders = append(this.modifiedFolders, mfolder)
		}
	}

	if !this.recursively || this.isMaxReached {
		return true
	}
	for _, fileInfo := range dirs {
		if !this.isProcessingSymFolders && fileInfo.IsSymlink {
			continue
		}
		absPath := filepath.Clean(fileInfo.AbsPath)
		if utils.SetContains(this.traversedDirs, absPath) {
			continue
		}
		this.startRescan(absPath, nil,  currentRelativePath+"/"+fileInfo.Name,  updateMeta, "", hashSuffix)
		if this.isMaxReached {
			break
		}
	}
	return true
}

/**
Return false if exceeding MAX_CHANGE_COUNT_CLIENT
*/
func (this *Rescan) handleFile(fileInfo *utils.RealFileInfo, mfolder *utils.ModifiedFolderExt, currentRelativePath string, newRowIndex *uint32, pathBin string, updateMeta bool,
	binRowMap map[string]*utils.IndexBinRow, newItemMap map[string]bool, deletedItemMap map[string]*utils.IndexBinRow, dirs *[]*utils.RealFileInfo, hashSuffix string) bool {
	ret := true
	isDirectory := fileInfo.IsDir
	name := fileInfo.Name
	//indexInFileName := -1
	if !isDirectory {
		name, _, _ = processFileName(fileInfo.Name)
	}
	fKey := utils.CalculateFileNameKey(name, isDirectory, mfolder.FolderHash, hashSuffix)
	var newlyAddedRow *utils.ModifiedRow
	loweredName := strings.ToLower(name)

	if row, ok := binRowMap[fKey]; ok { //the file/folder is found in existing registry.
		config := utils.LoadConfig()
		if config.Mode != utils.CONFIG_MODE_NEW_ONLY {
			if !isDirectory {
				permissionChanged := (row.FileMode != fileInfo.Permission)
				if utils.IsWindows() {
					permissionChanged = false
				} //We don't care permission changes on Windows.
				if row.LastModified != fileInfo.LastModified || row.FileSize != fileInfo.Size || permissionChanged {
					accessible, hash := checkAccessAndHash(fileInfo, currentRelativePath+"/"+name, hashSuffix)
					if !accessible {
						return true
					}
					utils.Debugf("row.FileMode:%d, fileInfo.Permission:%d, row.absPath:%s, fileHash:%s, row.fileHash:%s", row.FileMode, fileInfo.Permission, fileInfo.AbsPath, hash, row.ToHashString())
					fileInfo.Hash = hash
					this.fileHashMap[mfolder.FolderHash+fKey] = fileInfo
					hasChanged := (hash != row.ToHashString())
					if permissionChanged || hasChanged {
						if updateMeta {
							var opMode uint8
							if hasChanged {
								opMode = utils.MODE_MODIFIED_CONTENTS
							} else {
								utils.Debugf("MODE_MODIFIED_PERMISSIONS. FileHash:%s, oldPerm:%o, newPerm:%o\n", name, row.FileMode, fileInfo.Permission)
								opMode = utils.MODE_MODIFIED_PERMISSIONS
							}
							newRow := updateRowAt(pathBin, row.Index, fKey, fileInfo, &hash, 0, opMode)
							isDuplicate := false
							generateHashObject(fileInfo.AbsPath, hash, &isDuplicate)
							utils.Debugf("Add new row, Index:%d, opMode:%d, Name:%s, newRow.len:%d\n", row.Index, opMode, name, len(newRow))
							if newlyAddedRow, ok = AddRow(mfolder, row.Index, opMode, &newRow, name, isDirectory, this); !ok {
								ret = false
							}
						}
					}
				}
			}
			delete(binRowMap, fKey)
		}
	} else { //the file/folder is not found.
		accessible, hash := checkAccessAndHash( fileInfo, currentRelativePath+"/"+name, hashSuffix)
		if !accessible {
			return true
		}
		fileInfo.Hash = hash
		var row *utils.IndexBinRow
		if r, ok := deletedItemMap[name]; ok {
			utils.Debugf("Deleted map contains: %s\n", name)
			row = r
		}
		if row != nil && utils.IsFileModeDeleted(row.FileMode) {
			ok := true
			if !isDirectory {
				isDuplicate := false
				generateHashObject(fileInfo.AbsPath, hash, &isDuplicate)
				if newlyAddedRow, ok = AddRow(mfolder, row.Index, utils.MODE_REINSTATE_FILE, nil, name, isDirectory, this); !ok {
					ret = false
				}
			} else if !this.ignoreDirectory{
				if newlyAddedRow, ok = AddRow(mfolder, row.Index, utils.MODE_REINSTATE_DIRECTORY, nil, name, isDirectory, this); !ok {
					ret = false
				}
			}
		} else {
			skip := false
			if !utils.SetContains(newItemMap, loweredName) {
				newItemMap[loweredName] = true
			} else { //names only diff in case
				if isDirectory { //must be renamed locally and on the server. Local OS is case sensitive.
					suffix := fmt.Sprintf(" (Conflict %d)", *newRowIndex)
					newName := name + suffix
					if utils.Rename(fileInfo.AbsPath, fileInfo.AbsPath+suffix) != nil {
						utils.Infof("Failed to rename directory: %s", fileInfo.AbsPath)
						skip = true
					} else {
						name = newName
						fKey = utils.CalculateFileNameKey(name, true, mfolder.FolderHash, hashSuffix)
						h := utils.GetFolderPathHash(currentRelativePath + "/" + name)
						newFileInfo := utils.CopyRealFileInfo(fileInfo) //must make a new copy here!
						newFileInfo.Hash = h
						newFileInfo.AbsPath = fileInfo.AbsPath + suffix
						newFileInfo.Name = newName
						this.fileHashMap[mfolder.FolderHash+fKey] = newFileInfo
						fileInfo = newFileInfo //set fileInfo so the new value will be added dirs array
					}
				}
			}
			ok := true
			if isDirectory {
				if !this.ignoreDirectory {
					if !skip {
						//utils.Debugf("New Local, rowIndex:%d; oldHash:%s, currentHash:%s, Name:%s, fkey:%s, fileHash:%s\n", *newRowIndex, hash, fileInfo.Hash, name, fKey, fileInfo.Hash)
						if newlyAddedRow, ok = AddRow(mfolder, *newRowIndex, utils.MODE_NEW_DIRECTORY, nil, name, isDirectory, this); !ok {
							ret = false
						}
					}
				}
			} else {
				if newlyAddedRow, ok = AddRow(mfolder, *newRowIndex, utils.MODE_NEW_FILE, nil, name, isDirectory, this); !ok {
					ret = false
				}
			}
			(*newRowIndex)++
		}

		this.fileHashMap[mfolder.FolderHash+fKey] = fileInfo
	}
	if newlyAddedRow != nil {
		checkXattr(newlyAddedRow, fileInfo.AbsPath)
	}
	if fileInfo.IsDir {
		*dirs = append(*dirs, fileInfo)
	}
	return ret
}

func (this *Rescan) fixRenaming() {
	var toRemove []int
	config := utils.LoadConfig()
	for _, folder := range this.modifiedFolders {
		toRemove = nil
		sha := folder.FolderHash
		subPath := utils.HashToPath(sha)
		path := utils.GetTopTreeFolder() + subPath
		pathBin := path + ".bin"
		var binDataArray []byte

		// To store the keys in slice in sorted order, from small to large
		keys := make([]int, len(folder.Rows))
		kindex := 0
		for k := range folder.Rows {
			keys[kindex] = int(k)
			kindex++
		}
		sort.Ints(keys)
		utils.Debugf("FixNaming, folder:%s", folder.FolderHash)
		for _, k := range keys {
			index := uint32(k)
			row := folder.Rows[index]

			opMode := (row.GetOpMode())
			fKey := utils.CalculateFileNameKey(row.FileName, row.IsDir, folder.FolderHash, folder.Repository.HashSuffix)

			fileInfo, _ := this.fileHashMap[folder.FolderHash+fKey] // GetRealFileInfo(absPath);
			if fileInfo == nil {
				//utils.Debugf("NULL FileInfo: %s\n", absPath)
				continue
			}
			utils.Debugf("Row, opMode:%d, Index:%d, fkey:%s;ignoreDeletes:%v; file:%s, fileHash:%s\n", opMode, index, fKey, this.ignoreDeletes, row.FileName, fileInfo.Hash)
			if opMode == utils.MODE_REINSTATE_FILE && config.Mode != utils.CONFIG_MODE_NEW_ONLY {
				hash := fileInfo.Hash // getHash(absPath, false, "")
				utils.Debug("Reinstate file. name:", row.FileName, "; hash:", fileInfo.Hash)
				newRow := updateRowAt( pathBin, index, row.GetRowFileNameKey(), fileInfo,  &hash, 0, utils.MODE_REINSTATE_FILE)
				utils.Debug("Reinstate, row:", utils.ToHex(newRow))
				row.Row = newRow
			} else if opMode == utils.MODE_NEW_FILE || (opMode == utils.MODE_NEW_DIRECTORY && !this.ignoreDirectory) {
				hash := fileInfo.Hash // this.fileHashMap[fKey];//getHash(absPath, opMode == utils.MODE_NEW_DIRECTORY, relativePath)
				if !this.recursively && opMode == utils.MODE_NEW_DIRECTORY {
					for  _,d := range this.deletedFiles {
						data := d[0];
						fileNameKey := utils.CalculateFileNameKey(fileInfo.Name, fileInfo.IsDir, folder.FolderHash, folder.Repository.HashSuffix)
						row.OldFolderHashAndIndex = data.hash;
						newRow := updateRowAt( pathBin, data.index, fileNameKey, fileInfo,  &hash, 0, utils.MODE_RENAMED_DIRECTORY)
						row.Row = newRow
						row.OperationMode = utils.MODE_RENAMED_DIRECTORY;
						folder.Rows[data.index] = row;
						if(data.index != index) {
							toRemove = append(toRemove, int(index))
						}
						break;
					}
				}else {
					skip := false
					var dataArr []*DeletedRowData
					var dataFound bool
					if (!this.ignoreDeletes) {
						if dataArr, dataFound = this.deletedFiles[hash]; dataFound {
							data := dataArr[0];
							if data.folderHash == folder.FolderHash {
								data.notToUpdateRow = true
								//this.deletedFiles[hash] = data
								skip = true
								newFileName := fileInfo.Name
								fileNameKey := utils.CalculateFileNameKey(fileInfo.Name, fileInfo.IsDir, folder.FolderHash, folder.Repository.HashSuffix)
								newRow := updateRowAt(pathBin, data.index, fileNameKey, fileInfo, &hash, 0, utils.MODE_RENAMED_FILE)
								data.row.Row = newRow
								toRemove = append(toRemove, int(index))
								data.row.OperationMode = utils.MODE_RENAMED_FILE
								//data.fileInfo = fileInfo;
								data.hash = hash
								data.row.FileName = newFileName
							}
						} //end of if deletedFiles.contains()
					}

					if !skip {

						binDataArray = nil
						binDataArray = make([]byte, utils.FILE_INFO_BYTE_COUNT)
						if dataFound { //moved from other folder
							data := dataArr[0];
							row.OperationMode = utils.MODE_RENAMED_FILE
							if data.row != nil {
								data.row.OperationMode = utils.MODE_MOVED_FILE
							}
							data.newFolderHash = folder.FolderHash
							row.OldFolderHashAndIndex = fmt.Sprintf("%s%s%d", data.folderHash, utils.SEPARATOR, data.index)
						}
						err := addNewItem(folder.FolderHash, binDataArray, index, fileInfo, hash, opMode, folder.Repository.HashSuffix)
						if err == nil {
							utils.Debugf("new item folder:%s, new row Index:%d， row:%s\n", folder.FolderHash, index, utils.ToHex(binDataArray))
							row.Row = binDataArray
							folder.Rows[index] = row
						}else {
							if !this.keepCorruptedFile {
								toRemove = append(toRemove, int(index))
							}
						}
						//newRowIndex++;
					}else{
					}
				}

			}else{
			}
		} // end of foreach row

		if len(toRemove) > 0 {
			for _, i := range toRemove {
				delete(folder.Rows, uint32(i))
			}
		}
	} //end of foreach folder

	if config.Mode != utils.CONFIG_MODE_NEW_ONLY {
		for key, dataArr := range this.deletedFiles {
			for _,data := range dataArr {
				if !data.notToUpdateRow {
					var newRow []byte
					fileNameKey := data.fileNameKey;
					utils.Debug("Get file name key for file:", data.fileName, "; folderHash:", data.folderHash, "; key: ", fileNameKey, "; hash: ", key)
					if data.row != nil && data.row.OperationMode == utils.MODE_MOVED_FILE {
						newRow = updateRowAt(data.binFilePath, data.index, fileNameKey, nil, &key, 0, uint8(utils.MODE_MOVED_FILE))
					} else {
						newRow = updateRowAt(data.binFilePath, data.index, fileNameKey, nil, &key, 0, uint8(utils.MODE_DELETED_FILE))
					}
					if data.row != nil {
						data.row.Row = newRow
					}
				}
			}
		}
	}
}

func (this *Rescan) fixSymlinks(fis []os.FileInfo, currentRelativePath, sourceAbsPath, parentSha string) []*utils.RealFileInfo {
	var fileNames []*utils.RealFileInfo
	var valid bool
	//sort.Slice(fis, func(i, j int) bool { return fis[i].Name() < fis[j].Name() }) //sort by file name
	//sort.Sort(ByFileSize(fis)) //smaller ones are in the front
	sort.Slice(fis, func(i,j int) bool{
		if fis[i].IsDir() {
			return fis[i].Name() < fis[j].Name()
		}
		if(fis[i].ModTime().Equal(fis[j].ModTime())){
			return fis[i].Size() < fis[j].Size()
		}else {
			return fis[i].ModTime().Before(fis[j].ModTime())
		}
	})
	for _, fileInfo := range fis {
		valid = true
		fileName := fileInfo.Name()
		//utils.Debug("Under dir:", currentRelativePath, ", file:",fileName);
		path := filepath.Join(sourceAbsPath, fileName)

		if fileName == "." || fileName == ".." || !this.FilterFile(currentRelativePath + "/" + fileInfo.Name(), fileInfo) {
			//utils.Debug("Filter out:", path)
			continue
		}
		var rfi *utils.RealFileInfo
		if utils.IsSymlink(fileInfo) {
			absPath, b := getRealPath(path)
			//utils.Debugf("Symlink path:%s, realPath:%s\n", path, absPath)
			valid = b
			if valid {
				fi, err := os.Stat(absPath) //FileExists
				if err != nil {
					valid = false
				} else if fi.IsDir() {
					rfi = utils.NewRealFileInfo(fi, absPath)
					rfi.Name = fileName //Must use symlink's file RemoteName instead of real file's RemoteName
					rfi.ParentHash = parentSha
					rfi.RelativePath = currentRelativePath + "/" + fileName
					rfi.IsSymlink = true
					utils.Debug("rfi, parentHash:", rfi.ParentHash, "; relativePath: ", rfi.RelativePath)
					this.symFolders = append(this.symFolders, rfi)
				} else if fi.Mode().IsRegular() {
					//                    addFile(currentRelativePath, newSrcFileInfo);
					rfi = utils.NewRealFileInfo(fi, absPath)
					rfi.Name = fileInfo.Name()
				} else {
					valid = false
				}
			}
		}
		if valid {
			if rfi == nil {
				rfi = utils.NewRealFileInfo(fileInfo, filepath.Join(sourceAbsPath, fileInfo.Name()))
			}
			if rfi != nil {
				fileNames = append(fileNames, rfi)
			}
		}
	}
	return fileNames
}

func sendConfirmDeviceID(userID  string, deviceID uint32, accessToken []byte, c utils.SyncResultClient) {
	dataRequest := utils.UserRequest{
		UserID:     userID,
		DeviceID:   deviceID,
	}
	utils.SetUserRequestNowWithAccessToken(&dataRequest, userID, fmt.Sprintf("%d", deviceID), accessToken)
	dataRequest.Action = "device"
	c.SendData(context.Background(), &dataRequest)

}

var rpcMutex = &sync.Mutex{}

func encryptFileName(i interface{}){
	row := i.(* utils.ModifiedRow)
	//utils.Debug("TO encrypt:", row.FileName)
	row.SetDisplayFileName(row.FileName) //encryptFileName now
}

//return error message if any. ("" indicates no error)
//@return 0 : ok; 1: server returns nil or other errors ; 2: toomany changes on server, require resetGetAll
func (rescan Rescan) rpcSync(headers map[string]string,   notify bool,  f func([]*utils.ModifiedFolderExt) error, deletes *syncmap.Map, changeCount int) (string,int32) {
	rpcMutex.Lock()
	defer rpcMutex.Unlock()
	utils.Debug("Enter rpcSync -------------- ShareState: ", rescan.shareState)
	msg := &utils.ModifiedData{}
	n := 0
	if  rescan.modifiedFolders != nil {
		n = len( rescan.modifiedFolders)
	}
	msg.Folders = make([]*utils.ModifiedFolder, n)

	var wg sync.WaitGroup
	p, _ := ants.NewPoolWithFunc(50, func(i interface{}) {
		encryptFileName(i)
		wg.Done()
	})
	defer p.Release()

	utils.Debug("To start encrypt filenames. changes:", changeCount)
	text := "To encrypt file names ..."
	if(n>0){
		text = fmt.Sprintf("To encrypt %d file names ...", changeCount)
	}
	utils.SendToLocal(utils.MSG_PREFIX + text)
	for i := 0; i < n; i++ {
		isEncrypted :=  rescan.modifiedFolders[i].Repository.EncryptionLevel > 0
		if (isEncrypted) {
			for k, row := range  rescan.modifiedFolders[i].ModifiedFolder.Rows {
				var shareFolder *utils.ShareFolder;
				//utils.Debug("~~~~~~~~~~~ To encrypt file namekey: ", row.GetRowFileNameKey())
				if (rescan.shareState != utils.REPO_SHARE_STATE_ALL) {
					shareFolder = utils.GetShareFolderByRepoHash(utils.GetTopTreeFolder(),  rescan.modifiedFolders[i].ModifiedFolder.RepoHash);
				}
				if shareFolder != nil {
					row.SetDisplayFileNameForShareFolder(row.FileName,  rescan.modifiedFolders[i].ModifiedFolder.FolderHash, shareFolder)
				} else {
					wg.Add(1)
					_ = p.Invoke(row)
					//row.SetDisplayFileName(row.FileName) //encryptFileName now
				}
				rescan.modifiedFolders[i].ModifiedFolder.Rows[k] = row;
			}
		}
		msg.Folders[i] = & rescan.modifiedFolders[i].ModifiedFolder
	}
	utils.Debug("To wait for pool to finish.")
	wg.Wait()
	utils.SendToLocal(utils.MSG_PREFIX + "File names have been encrypted.")

	if headers == nil {
		headers = make(map[string]string)
	}
	headers["originator"] = rescan.owner;
	headers["suffix"] = utils.GetHashSuffix()
	if(rescan.owner != ""){//REPO_SHARE_STATE_SHARE
		headers["share"] = fmt.Sprintf("%d", utils.REPO_SHARE_STATE_OWNER)
	}else {
		headers["share"] = fmt.Sprintf("%d", rescan.shareState)
	}
	utils.Debug("rpcSync.Headers:", headers)
	msg.Headers = headers
	msg.Notify = notify

	configDir := utils.GetAppHome()
	offsetFile := filepath.Join(configDir, utils.OFFSET_FILE)
	offsetFileExists := utils.FileExists(offsetFile)
	if offsetFileExists {
		offset, err := utils.ReadString(offsetFile)
		if err == nil {
			headers["offset"] = offset
		}
	}

	if f != nil {
		f( rescan.modifiedFolders);
		return "", 1;
	} else if  rescan.modifiedFolders != nil {
		utils.SendToLocal("startUpload") //upload files to cloud
		if ok, m := rescan.doUploads( rescan.modifiedFolders, deletes, rescan.shareState); !ok {
			utils.Debug("Failed to uploads...")
			utils.SendToLocal("failUpload")
			return "", 1
		} else {
			msg.Objects = m
		}
	}

	return rescan.uploadStagingAndSendout(msg, true)
}

//@return 0 : ok; 1: server returns nil or other errors ; 2: toomany changes on server, require resetGetAll
func (rescan Rescan) uploadStagingAndSendout(msg * utils.ModifiedData, toSaveUploadStagingTask bool) (string,int32){
	if(toSaveUploadStagingTask){
		saveUploadStagingTask(msg, rescan.shareState, rescan.owner)
	}
	if b, errMsg := rescan.uploadStaging() ; !b{
		utils.Debug("uploadStaging returned error:", errMsg)
		return errMsg, 1;
	}
	utils.SendToLocal("stopUpload")
	AddFileID(msg.Objects);
	config := utils.LoadConfig()
	configDir := utils.GetAppHome()
	offsetFile := filepath.Join(configDir, utils.OFFSET_FILE)
	offsetFileExists := utils.FileExists(offsetFile)
	utils.Debug("Before sendRequestToMainServer, objects.size: ", len(msg.Objects))
	serverResponse, m := utils.SendSyncRequestToMainServer(msg, rescan.shareState, rescan.owner)
	//utils.Debug("Resp.code:", serverResponse.Code)
	if(serverResponse == nil){
		utils.Debug("sendRequestToMainServer returned nil response!")
		utils.SendToLocal("")
		return m, 1;
	}else if serverResponse.Code == utils.SERVER_CHANGE_TOO_MANY {
		//too many changes on server, do resetGetAll instead
		return m, 2
	}
	utils.Debugf("\n\n============== After sendRequestToMainServer, in.objects.Size: %d, updates.size:%d, tasks.size:%d\n", len(serverResponse.Objects), len(serverResponse.FolderUpdates), len(serverResponse.Tasks))
	homeDir := utils.GetAppHome()
	DoSaveObjectsToFile(msg.Objects, homeDir, false , false, "")

	var nonLocalTasks, updateLocalTasks []*utils.WriteTask
	for _, task := range serverResponse.Tasks {
		if task.Side == utils.SIDE_SERVER_ONLY {
			continue
		}

		if task.Mode == utils.TASK_UPDATE_LOCAL && config.Mode != utils.CONFIG_MODE_NEW_ONLY {
			updateLocalTasks = append(updateLocalTasks, task)
		} else {
			nonLocalTasks = append(nonLocalTasks, task)
		}
	}

	tasks := nonLocalTasks
	tasks = append(tasks, updateLocalTasks...)

	utils.SaveTasksCommit(utils.GetTasksFolder(), tasks) //nonLocalTasks, updateLocalTasks);
	if offsetFileExists {
		utils.RemoveFile(offsetFile)
	}

	rescanRet := int32(1);
	if len(serverResponse.Objects) > 0 || len(serverResponse.FolderUpdates) > 0 {
		SaveUpdateDatTaskCommit(utils.GetUpdateDatTasksFolder(), serverResponse.Objects, serverResponse.FolderUpdates, rescan.shareState)
		if updateDatFilesAndCloseGap(serverResponse.Objects, serverResponse.FolderUpdates){
			//just initialized share folder, needs to update
			rescanRet = 0;
		}
		utils.RemoveFile(utils.GetUpdateDatTasksFolder())
	}

	utils.Debug("To call ExecuteClientSideTasks, tasks.len: ", len(tasks))
	ExecuteClientSideTasks(tasks)
	removeUploadStagingTask();
	utils.Debug("====================== rpcSync returned\n\n\n")
	return "", rescanRet
}

func (rescan Rescan) doUploads(changes []*utils.ModifiedFolderExt, deletes *syncmap.Map, shareState int32) (bool, map[string][]byte) {
	config := utils.LoadConfig()
	threadCount := uint(config.ThreadCount);
	if(threadCount < 4){
		threadCount = 4;
	}

	objects := new(syncmap.Map) // cmap.New()

	i := 0
	var repo *utils.Repository
	n := len(changes)

	//clean up staging area before uploading
	_ = utils.RemoveAllSubItems(utils.GetStagingFolder());
	_ = utils.RemoveAllSubItems(utils.GetFolder("tmp") + "pack/");

	//For local and server, upload files directly; for clouds, just move files to staging area, then later we will call uploadStagingToCloud()
	for j := 0; j <= n; j++ {
		if (j == n) || ( repo != nil && repo.Name != "" && changes[j].Repository.Name != repo.Name) {

			utils.Debugf("toUpload. i:%d, j:%d, n:%d, repo:%v,  ", i, j, n, repo)
			_ = rescan.uploadToCloud(repo, changes[i:j], objects,  deletes, shareState);
			if j == n {
				break
			}
			i = j
		}
		repo = changes[j].Repository
	}
	utils.Debug("To wait for all compress jobs done")
	compressWait.Wait() //wait for all jobs done
	utils.Debug("All compress jobs done.")
	//utils.Debug("All files have been uploaded. To send request to server.")
	return true, ConvertToMap(objects)
}

func (rescan Rescan) uploadStaging()(bool, string){
	//Now to process staging folder
	var errMsg string;
	staging := utils.GetStagingFolder();
	if(utils.FileExists(staging)) {
		size, count, _ := GetStagingFolderSize(staging); // getAllFileSize(changes);
		if (size > 0) {
			t1 := uint32(time.Now().Unix())
			utils.Debug("To call uploadStagingToCloud --------total file size: ", size, "; file count:", count)
			utils.SendToLocal(fmt.Sprintf("%sTo upload files, total size: %d", utils.MSG_PREFIX, size))
			var b bool;
			b, errMsg = rescan.uploadStagingToCloud()
			t2 := uint32(time.Now().Unix())
			utils.Debug("uploadStagingToCloud returned --------size: ", size)
			if b {
				utils.Info("Finished uploading size: ", size, ". Time used: ", t2-t1)
			}else{
				utils.Error("Couldn't finish uploading")
				//upload failed. restart itself
				utils.Restart(false)
			}


			_ = utils.RemoveAllSubItems(utils.GetStagingFolder());
			_ = utils.RemoveAllSubItems(utils.GetFolder("tmp") + "pack/");
			if (!b) {
				return false, errMsg
			}
		}
	}
	return true, ""
}

/**
The staging folder contains files whose contents pointing the real files
 */
func GetStagingFolderSize(path string) (int64, uint32, error) {
	var size int64
	var count uint32 = 0;
	err := filepath.Walk(path, func(currentPath string, info os.FileInfo, err error) error {
		if !info.IsDir() {
			if buf, err := ioutil.ReadFile(currentPath); err == nil {
				p := strings.TrimSpace(string(buf))
				if fi, err := os.Stat(p); err == nil {
					size += fi.Size()
					count ++;
				}

			}
		}
		return err
	})
	return size, count, err
}

func (rescan Rescan) uploadStagingToCloud() (bool, string) {
	var errMsg string

	folders, _ := utils.GetSubFolders(utils.GetStagingFolder())

	done := make(map[string]bool)
	var err error
	retries := 10
	ticker := time.NewTicker(time.Second * 2)
	go updateStats(ticker)
	defer stopTicker(ticker)
	var src  string;
	repos := utils.GetRepositoryList();
	shares := utils.GetShareFolderList(repos);
	if(shares != nil) {
		repos = append(repos, shares...)
	}
	for i := 0; i < retries; i++ {
		err = nil
		for _, f := range folders {
			for _, r := range repos {
				//utils.Debug("f.Name: ", f.Name(), "; r.Hash: ", r.Hash)
				if f.Name() == r.Hash {
					for _, remote := range r.Remote {
						if remote.Type != utils.REMOTE_TYPE_LOCAL_NFS {
							key := f.Name() + "@" + remote.Name
							if utils.SetContains(done, key) {
								continue
							}
							src = utils.GetStagingFolder() + f.Name() + "/"
							src = filepath.Clean(src)
							root := remote.Root
							if(r.Owner != ""){
								m := utils.GetUserInfo(r.Owner)
								if m != nil {
									prefix := string(m["prefix"])
									ts := strings.Split(remote.Root, "/")
									root = ts[0] + "/" + prefix + "/";
								}
							}
							args := []string{src, remote.Name + ":" + root}
							utils.Debug("---uploadStagingToCloud. srcStagingFolder: ", src, "; remote.type:", remote.Type, "; args are ", args)
							createBucketIfNecessary()
							fsrc, fdst := cmd.NewFsSrcDst(args)
							if fsrc == nil || fdst == nil {
								utils.Error("Cannot create file system")
								return false, "cannot create file system"
							}
							utils.Debug("To call fs.CopyDir. fsrc: ", fsrc, ". fdest: ", fdst, "; REMOTE: ", remote.Name)
							s := accounting.Stats(context.Background())
							errCount := s.GetErrors()
							e := fsync.CopyDir(context.Background(), fdst, fsrc, true)
							utils.Debug("CopyDir returned ------------------------------------------------------------------")
							if e == nil {
								s = accounting.Stats(context.Background())
								if s.GetErrors() > errCount {
									e = errors.New("cannot upload file to remote")
								}
							}
							if e == nil {
								if(remote.Type != utils.REMOTE_TYPE_OFFICIAL) {
									var buf bytes.Buffer
									if e = operations.ListDir(context.Background(), fdst, &buf); e == nil { //ListDir only check if the top directory exists. It's not complete. Needs more complete solution later.
										res := buf.String()
										utils.Debug("listdir:", res)
									} else {
										utils.Debug("listdir failed, error is ", e)
										etext := fmt.Sprintf("%v", e)
										errMsg = etext
										if strings.Index(etext, "invalid_access_token") >= 0 {
											errMsg = "Invalid access token."
										} else if strings.Index(etext, "connection refused") >= 0 {
											errMsg = "Cannot connect to the cloud provider's server."
										}
										return false, errMsg
									}
								}
								done[key] = true

							} else {
								err = e;
								utils.Error("CopyDir error. src: ", src, "; Error:", e)
							}
						}
					}

					break
				}
			}
		}
		if err == nil {
			break
		}
		utils.Debug("To sleep ... seconds.")
		time.Sleep(2* 60 * time.Second)
	}
	if err != nil {
		utils.Error("Error. Before returning from doUploads, src: ", src, "; Error:", err)
		return false, errMsg
	}
	return true, errMsg
}

func stopTicker(ticker *time.Ticker) {
	utils.Debug("To stop ticker")
	ticker.Stop()
	s := accounting.Stats(context.Background())
	s.ResetCounters()
}

var gUploadedBytes int64;
var gCurrentUploadedBytes int64;
func updateStats(ticker *time.Ticker) {
	var uploadedBytes = int64(0)
	tmp := int64(0)
	progress := ""
	count := 0
	utils.Debug("Enter updateStats")
	for range ticker.C {
		text := ""
		s := accounting.Stats(context.Background())
		bs := s.GetBytes() ////Returns   number of bytes transferred, number of files being transferred, file names being transferred.
		utils.Debug("stats. transferred:", bs)
		if bs == 0 {
			continue
		}
		if uploadedBytes > 0 || gUploadedBytes > 0 {
			text = "Uploaded " + utils.ToUnit(uploadedBytes + gUploadedBytes) ;
		}
		if count == 15 {
			progress = ""
			count = 0
		} else {
			progress += "●"
			count++
		}
		text += " " + progress
		if bs > tmp && tmp != 0 {
			uploadedBytes = tmp
		}
		tmp = bs
		gCurrentUploadedBytes = uploadedBytes;
		utils.Debug("bs:" , bs , "; uploadedBytes:", uploadedBytes, "; gUploadedBytes:", gUploadedBytes, "; time: ", time.Now() ,";Stats update text: <", text+">")
		utils.SendToLocal(utils.MSG_PREFIX + text)
	}

	utils.Debug("Exit updateStats")
}

func ConvertToMap(objects *syncmap.Map) map[string][]byte {
	m := make(map[string][]byte)
	objects.Range(func(k, v interface{}) bool {
		fileMeta := v.(*utils.FileMeta);
		m[k.(string)] = []byte(utils.FileMetaToString(fileMeta)) //or use fmt.Sprintf("%v", k);
		return true
	})
	utils.ClearFileNameToID()
	return m
}
func AddFileID(objects map[string][]byte) map[string]string {
	m := make(map[string]string)
	for k, v := range objects{
		fileMeta := utils.StringToFileMeta(string(v))
		if(fileMeta.T == utils.FILE_META_TYPE_REGULAR || fileMeta.T == utils.FILE_META_TYPE_THUMBNAIL || fileMeta.T == utils.FILE_META_TYPE_PACK || fileMeta.T == utils.FILE_META_TYPE_CHUNKS || fileMeta.T == utils.FILE_META_TYPE_DIFF){
			if val, f := utils.GetFileID(fileMeta.P) ; f {
				fileMeta.P += utils.META_PATH_ID_SEPARATOR + val;
			}
		}
		val := utils.FileMetaToString(fileMeta)
		objects[k] = []byte(val)
	}
	utils.ClearFileNameToID()
	return m
}

//the utils.SHARED_HASH must be in the front, because if there is a new share, getShareInit should be
//invoked first to get initial data, then subsequent row updates can apply.
func reorderUpdates(folderUpdates map[string]*utils.ServerFolderUpdates) [] *utils.ServerFolderUpdates{
	var ret [] *utils.ServerFolderUpdates ;
	if u, ok := folderUpdates[utils.SHARED_HASH]; ok{
		ret = append(ret, u)
	}
	for k, folder := range folderUpdates{
		if(k == utils.SHARED_HASH){
			continue
		}
		ret = append(ret, folder)
	}
	return ret;
}

func updateDatFilesAndCloseGap(objects map[string][]byte, folderUpdates map[string]*utils.ServerFolderUpdates) bool{
	//Update *.dat file first:
	ret := false;
	if len(objects) > 0 {
		DoSaveObjectsToFile(objects, utils.GetAppHome(), false, false, "")
	}

	//close the gap with the server log:
	updateLocals := make(map[string]map[uint32]*utils.ModifiedRow)
	renameMap := make(map[string]string)
	var includes []uint32;
	updates := reorderUpdates(folderUpdates)
	for _, folder := range updates {
		folderHash := folder.FolderHash
		shareFolders := utils.GetShareFoldersOnClient(folderHash)
		if (shareFolders != nil) {
			includes = utils.GetAllShareFolderIncludes(shareFolders);// utils.StringToUints(shareFolder.Includes);
		}else{
			includes = nil;
		}
		utils.Debug("In updateDatFilesAndCloseGap, folderHash:", folderHash)
		base := utils.GetTopTreeFolder() + utils.HashToPath(folderHash)
		binFileName := base + ".bin"
		binMap := make(map[uint32]*utils.ModifiedRow)
		for _, row := range folder.Logs {
			appendLog(binFileName, row.Row)
			binMap[row.GetRowIndex()] = row
		}

		updateLocalMap := make(map[uint32]*utils.ModifiedRow)
		// To store the keys in slice in sorted order, from small to large
		keys := make([]int, len(binMap))
		kindex := 0
		for k := range binMap {
			keys[kindex] = int(k)
			kindex++
		}
		sort.Ints(keys)
		for _, k := range keys {
			index := uint32(k)
			row := binMap[index]
			if(includes != nil &&  !utils.UintsContains(includes, row.GetRowIndex())){
				continue
			}
			var name string
			fkey := row.GetRowFileNameKey()
			name, foundKey := utils.DbGetStringValue(fkey, true) //items.get(fkey)
			utils.Debugf("index:%d, fkey:%s, Name:%s, foundKey: %v, NameKey:%s\n", index, fkey, name, foundKey, row.GetRowFileNameKey())
			if !foundKey {
				//new name
				r := utils.GetRowAt(binFileName, index)
				if(r != nil) {
					oldName, found := utils.DbGetStringValue(r.FileNameKey, true);
					if (found) {
						renameMap[row.FileName] = oldName;
					}
				}
				utils.NamesDbSetStringValue(fkey, row.FileName)
			}
			utils.Debugf("In folder:%s, Index:%d, Name:%s, opMode:%d\n", folderHash, index, name, row.OperationMode)
			updateRowAtWithBytesNoAppendLog(folderHash, base, index, row.Row, true, row.Attribs)

			if(folderHash == utils.SHARED_HASH){
				io := row.GetIndexBinRow()
				utils.Debug("Shared, index:", index, "; row.hash: ", io.ToHashString());
				CallShareFolderInit(row.Attribs);
				ret = true
			}

			updateLocalMap[index] = row
		}

		updateLocals[folderHash + "," + folder.RepoHash] = updateLocalMap
	}
	repos := utils.GetRepositoryMapBy(true);
	db := utils.NewDownloadDb()
	defer db.Close()
	kvs := make(map[string][]byte)

	for key, m := range updateLocals {
		tokens := strings.Split(key, ",")
		folderHash := tokens[0]
		for _, row := range m {
			hasNew := row.OperationMode == utils.MODE_NEW_FILE || row.OperationMode == utils.MODE_NEW_DIRECTORY || (row.OperationMode == utils.MODE_RENAMED_FILE && len(row.OldFolderHashAndIndex) > 0)
			n := 0
			if hasNew{
				n = 1
			}
			fileHash := utils.GetHashFromRowBytes(row.Row)
			indexRow := row.GetIndexBinRow()
			val := fmt.Sprintf("%d,%d,%d,%d,%d", n, row.GetRowIndex(), indexRow.FileMode, indexRow.OperationMode, indexRow.FileSize)
			kvs[folderHash + "|" + fileHash] = []byte(val)
			//batch.Put([]byte(folderHash + "|" + fileHash), []byte(val))
		}
	}
	if err := utils.SetStringValues(db, kvs) ; err != nil{
		utils.Error("Failed to update file names.")
	}


	kvs = nil

	if utils.LoadConfig().Mode ==  utils.CONFIG_MODE_NEW_ONLY { //no need to update local files
		return ret
	}
	var deletes []string;
	for key, m := range updateLocals {
		tokens := strings.Split(key, ",")
		folderHash := tokens[0]
		repoHash := tokens[1]
		hasImage := false;
		for _, row := range m {
			utils.Debugf("================= Here, call updateLocalFile, folderHash:%s, fileHash:%s, fileName:%s\n", folderHash, row.GetIndexBinRow().ToHashString(), utils.GetDisplayFileName(row.FileName))
			hasNew := row.OperationMode == utils.MODE_NEW_FILE || row.OperationMode == utils.MODE_NEW_DIRECTORY || (row.OperationMode == utils.MODE_RENAMED_FILE && len(row.OldFolderHashAndIndex) > 0)
			fileHash := utils.GetHashFromRowBytes(row.Row)
			indexRow := row.GetIndexBinRow()
			if updateLocalFile(folderHash,fileHash, hasNew, row.GetRowIndex(), indexRow.FileMode, indexRow.OperationMode, indexRow.FileSize, row.FileName, renameMap) {
				deletes = append(deletes, folderHash + fileHash)
				//batch.Delete([]byte(folderHash + fileHash))
			}
			if IsImageFile(utils.GetDisplayFileName(row.FileName), true){
				hasImage = true;
			}
		}
		if(hasImage){
			if repo, ok := repos[repoHash]; ok {
				createThumbnailsForFolder(folderHash, nil, repo.EncryptionLevel == 1)
			}
		}
	}
	_ = utils.DeleteTasks(db, deletes)
	return ret;
}

func updateLocalFile( folderHash, fileHash string,  hasNew bool, rowIndex uint32, FileMode uint32, OperationMode uint8, FileSize int64, fileName string, renameMap map[string]string)  bool{
	ret := true
	repoTreePath := utils.GetTopTreeFolder()
	spath := utils.HashToPath(folderHash)
	baseFileName := repoTreePath + "/" + spath
	subPath := utils.HashToPath(fileHash)

	//binRow := row.GetIndexBinRow()
	isDirectory := utils.IsFileModeDirectory(FileMode);
	isDeleted  := utils.IsFileModeDeleted(FileMode);

	if hasNew {
		//rowIndex := row.GetRowIndex()
		//To call copyObjFromServer...filemode: %x, isDeleted: %v, fileHash:%s", binRow.FileMode, utils.IsFileModeDeleted(binRow.FileMode), fileHash)
		if err := updateLocalCopy(folderHash, baseFileName + ".bin", fileHash, rowIndex, isDirectory, isDeleted, FileSize == 0); err != nil {
			utils.Warn("Couldn't copy file from server. subpath: ", subPath)
			ret = false
		}
	} else if OperationMode == utils.MODE_MODIFIED_CONTENTS || OperationMode == utils.MODE_MODIFIED_PERMISSIONS ||
		OperationMode == utils.MODE_DELETED_FILE || OperationMode == utils.MODE_DELETED_DIRECTORY || OperationMode == utils.MODE_MOVED_FILE {
		if OperationMode != utils.MODE_DELETED_FILE && OperationMode != utils.MODE_DELETED_DIRECTORY {

			if err := updateLocalCopy(folderHash, baseFileName + ".bin", fileHash, rowIndex, isDirectory, isDeleted, FileSize == 0); err != nil {
				utils.Warn("Couldn't copy file from server. subpath: ", subPath)
				ret = false
			}
		} else {
			//utils.Debugf("To delete local copy. opMode:%d, baseFile: %s, subPath:%s, fileNameKey:%s", OperationMode, baseFileName, subPath, row.GetRowFileNameKey())
			deleteLocalCopy(repoTreePath, folderHash, fileHash, rowIndex)
		}
	}

	if OperationMode == utils.MODE_RENAMED_FILE && renameMap != nil {
		if val, ok := renameMap[fileName]; ok {
			renameLocalCopy(repoTreePath, folderHash, fileHash, rowIndex, val)
		}
	}

	if OperationMode == utils.MODE_DELETED_DIRECTORY {
		var subs []string
		processed := make(map[string]bool)
		RecursivelyGetSubsAndSetFolderDeleted(repoTreePath, fileHash, &subs, processed, nil)
	}
	return ret
}

func RecursivelyGetSubsAndSetFolderDeleted(repoTree, hash string, list *[]string, processed map[string]bool, taskList *[]*utils.WriteTask) {
	if utils.SetContains(processed, hash) {
		utils.Debugf("infinite loop: %s\n", hash)
		//os.Exit(3)
		return
	}
	processed[hash] = true
	subPath := utils.HashToPath(hash)
	base := repoTree + "/" + subPath
	pathBin := base + ".bin"
	rows := utils.ReadBin(pathBin, utils.FILTER_DIR_ONLY, nil)
	for _, row := range rows {
		RecursivelyGetSubsAndSetFolderDeleted(repoTree, row.ToHashString(), list, processed, taskList)
	}
	utils.Debugf("recursivelyGetSubsAndSetFolderDeleted, binFile:%s, Hash:%s\n", pathBin, hash)

	logWriter := utils.NewMetaBinIO(base, true)
	DeleteAllItems(pathBin, hash, nil, taskList, logWriter.GetRowCount())
}

func ExecuteClientSideTasks(tasks []*utils.WriteTask) {
	BatchExecuteTasks("", tasks)
}

func BatchExecuteTasks(user string, tasks []*utils.WriteTask) {
	//the reasons to execute nonLocal and then local is because if not, during executing TASK_UPDATE_LOCAL, some bin files may not be available so GetFullRelativePath may return wrong result.
	n := len(tasks)
	m := make(map[string][]byte)
	utils.Debug("Enter BatchExecuteTasks, tasks.len:", len(tasks))
	defer utils.Debug("Leave BatchExecuteTasks, tasks.len:", len(tasks))

	var deletes []string;
	isClientSide := user == "";
	for i := 0; i < n; i++ {
		task := tasks[i]
		if(task.Mode == utils.TASK_ADD_FILE_NAME){
			task.Mode = utils.TASK_IGNORE;
			line := task.Data
			pos := strings.Index(line, "=")
			if(pos > 0) {
				name := line[0:pos]
				value := line[pos+1:]
				m[name]=[]byte(value);
			}
			if isClientSide {
				deletes = append(deletes, utils.Int32ToHexString(task.ID))
			}
		}
	}
	utils.Debug("To batch set db values, len:", len(m))
	if(len(m)>0) {
		if user== "" {
			_ = utils.DbSetStringValues(m)
		}else{
			_ = utils.ServerNamesDbSetStringValues(user, m)
		}
	}

	utils.Debug("batch set returned. To execute tasks. n:", n)

	//process creat_bin tasks
	loopExecuteTasks(tasks, n, &deletes, user, utils.TASK_CREATE_BIN)

	//process append row
	baseBytes := make(map[string][]byte)
	for i := 0; i < n; i++ {
		task := tasks[i]
		if(task.Mode == utils.TASK_IGNORE ||task.Mode != utils.TASK_APPEND_BIN){
			continue;
		}
		task.Mode = utils.TASK_IGNORE
		if  bs, found := baseBytes[task.FolderHash]; found{
			bs = append(bs, task.Bytes...)
			baseBytes[task.FolderHash] = bs;
		}else{
			baseBytes[task.FolderHash] = task.Bytes;
		}
		handleTaskAttribs(task, isClientSide, user, false)

		if isClientSide {
			deletes = append(deletes, utils.Int32ToHexString(task.ID))
		}
	}

	var repoTreePath string
	if(user == ""){
		repoTreePath = utils.GetAppHome() + "/tree/";
	}else{
		repoTreePath = utils.GetUserRootOnServer(user) + "/tree/"
	}
	for k,v := range baseBytes{
		subPath := utils.HashToPath(k)
		base := repoTreePath + subPath
		WriteAndAppendLog( base, v, 0, false, true)
	}

	loopExecuteTasks(tasks, n, &deletes, user, utils.TASK_IGNORE)

	if user == "" { //on client side, to delete items in task db
		db := utils.NewDb(utils.GetTasksFolder() + "/data.db")
		if db != nil {
			_ = utils.DeleteTasks(db, deletes)
		}
	}
}

func loopExecuteTasks(tasks []*utils.WriteTask, n int, deletes * []string,  user string, onlyIncludeMode uint32){
	isClientSide := user == "";
	utils.Debug("Enter loopExecuteTasks, n:", n)
	for i := 0; i < n; i++ {
		//utils.Debug("To execute task:",i)
		task := tasks[i]
		if(task.Mode == utils.TASK_IGNORE){
			continue;
		}
		if(onlyIncludeMode != utils.TASK_IGNORE && task.Mode != onlyIncludeMode){
			continue;
		}
		if(user == "") {
			ExecuteTask(task, true,  "", false)
		}else{
			ExecuteTask(task, false,  user, false)
		}
		//if batch != nil {
		//	batch.Delete(utils.Int32ToBytes(task.ID))
		//}
		if(isClientSide) {
			*deletes = append(*deletes, utils.Int32ToHexString(task.ID))
		}
		task.Mode = utils.TASK_IGNORE
	}
	utils.Debug("Exit loopExecuteTasks")
}

func (this Rescan) countChanges() int {
	if len(this.modifiedFolders) == 0 {
		return 0
	}
	utils.Debug("----------------------CHANGES on Client Side----------------------------")
	totalChangedRows := 0
	for _, m := range this.modifiedFolders {
		utils.Debugf("Local Hash:%s, relativePath:%v\n", m.FolderHash, m.RelativePath)
		totalChangedRows += len(m.Rows)
		for _, row := range m.Rows{
			utils.Debug("Row.FileName:", row.FileName)
			utils.Debugf("Index: %d; Mode: %s, opMode:%d; birthTime:%d; FileMode:%o row.Hash:%s\n", row.GetRowIndex(), GetOpModeString(uint8(row.OperationMode)) ,  row.GetIndexBinRow().OperationMode,row.GetIndexBinRow().CreateTime, row.GetIndexBinRow().FileMode, row.GetIndexBinRow().ToHashString());
			if strings.HasPrefix(row.GetIndexBinRow().ToHashString(), "000000000000000"){
				utils.Error("000000 row hash-----------------")
			}

		}
	}
	utils.Debugf("TotalChangedRows:%d------------------------------------------------------------", totalChangedRows)
	return totalChangedRows
}

func (this *Rescan) clear() {
	this.deletedFiles = nil
	this.traversedDirs = nil
}

func addNewItem(folderHash string,  binDataArray []byte, index uint32, fileInfo *utils.RealFileInfo, hash string, opMode int32, hashSuffix string) error{
	fileNameKey := utils.CalculateFileNameKey(fileInfo.Name, fileInfo.IsDir, folderHash, hashSuffix)
	now := uint32(time.Now().Unix())
	//utils.Debugf("AddNewItem, fileKey: %s; fileName:%s, permission:%o", fileNameKey, fileInfo.Name, fileInfo.Permission&utils.PERMISSION_MASK)
	utils.WriteBytes(binDataArray, index, fileNameKey, fileInfo.CreateTime, fileInfo.Permission, now, fileInfo.LastModified, fileInfo.Size, utils.FromHex(hash), uint8(opMode), 0)
	var err error;
	if fileInfo.IsFile {
		isDuplicate := false
		err = generateHashObject(fileInfo.AbsPath, hash, &isDuplicate)
	}
	return err;
}

func CreateRow(fileKey string, fileName string) string {
	return fileKey + "=" + fileName
}

func getHash( absPath string, isDirectory bool, relativePath, hashSuffix string) string {
	if isDirectory {
		return utils.GetFolderPathHash(relativePath)
	} else {
		return utils.GetFileHash( absPath, hashSuffix)
	}
}

func generateHashObject(absPath string, hash string, isDuplicate *bool) error{
	dest := utils.GetTopObjectsFolder() + utils.HashToPath(hash) + utils.EXT_OBJ
	fiDir := filepath.Dir(dest)
	if !utils.FileExists(fiDir) {
		utils.MkdirAll(fiDir)
	}
	//FileSize := fileInfo.S();
	if utils.FileExists(dest) {
		*isDuplicate = true
	} else {
		if hash == utils.ZERO_HASH {
			utils.CreateZeroLengthFile(dest)
		} else {
			if err := utils.CopyFile(absPath, dest); err != nil{
				utils.Warn("Cannot copy file to obj file:", absPath, "; error:", err)
				utils.RemoveFile(dest);
				return err;
			}
		}
	}
	return nil;
}

func (this *Rescan) recursivelyDeleteSubs(hash string, processed map[string]bool) {
	if utils.SetContains(processed, hash) {
		return
	}
	processed[hash] = true
	subPath := utils.HashToPath(hash)
	pathBin := utils.GetTopTreeFolder() + subPath + ".bin"
	rows := utils.ReadBin(pathBin, utils.FILTER_DIR_ONLY,nil)
	for _, row := range rows {
		this.recursivelyDeleteSubs(row.ToHashString(), processed)
	}
	DeleteAllItems(pathBin, hash, this.deletedFiles, nil, 0)
}

//the relativePath is used to compute folder's text Hash
func checkAccessAndHash( fi *utils.RealFileInfo, relativePath string, hashSuffix string) (bool, string) {
	hash := getHash(fi.AbsPath, fi.IsDir, relativePath, hashSuffix)
	if hash == "" {
		utils.Info("FileHash cannot be read. ", fi.AbsPath, "; exists: ", utils.FileExists(fi.AbsPath), "; size: ", utils.FileSize(fi.AbsPath))
		return false, ""
	}
	return true, hash
}

func checkXattr(newlyAddedRow *utils.ModifiedRow, absPath string) {
	attribs := utils.GetAllXattrs(absPath)
	if attribs == nil {
		return
	}
	newlyAddedRow.Attribs = attribs
}

func containsFolderExt(folders []*utils.ModifiedFolderExt, folderHash string) *utils.ModifiedFolderExt {
	for _, folder := range folders {
		if folder.FolderHash == folderHash {
			return folder
		}
	}
	return nil
}

func ClearScan() {
	lastScanTime = time.Now().Unix()
	_fsMap = new(syncmap.Map)
	gUploadedBytes = 0;
	_ = utils.RemoveAllSubItems(utils.GetTopTmpFolder() + "/cache")
	_ = utils.RemoveAllSubItems(utils.GetStagingFolder())
	_ = utils.MkdirAll(utils.GetStagingFolder())
	_ = utils.RemoveAllSubItems(utils.GetPacksFolder())

	s := accounting.Stats(context.Background())
	s.ResetCounters()
}

func repoToFolderEx() ([]FolderEx, []FolderEx, map[string][]FolderEx) {
	var fex []FolderEx
	repos := utils.GetRepositoryList();
	config := utils.LoadConfig()
	for _, repo := range repos {
		if(repo.Hash == utils.SHARED_HASH){
			continue;
		}
		if(config.HasSelectedFolder() && config.IsSelectedFolder(repo.Name)){
			utils.Debug("repoToFolderEx, is selected:", repo.Name)
			continue
		}

		//utils.Debug("Repo.Name: ", repo.Name , "; hash: ", repo.Hash , "; local: ", repo.Local )
		f := FolderEx{}
		absPath, _ := filepath.Abs(repo.Local)
		f.absPath = filepath.Clean(absPath)
		f.relativePath = utils.ROOT_NODE + "/" + repo.Name
		//f.parentHash = utils.HEAD_TEXT
		f.repo = repo
		//utils.Debug("In repoToFolderEx; remote.RemoteName:", f.repo.Remote[0].RemoteName, "; type: ", f.repo.Remote[0].T)
		fex = append(fex, f)
	}
	var myShares []FolderEx
	shared := make(map[string][]FolderEx);
	repos = utils.GetShareFolderList(repos);
	for _, repo := range repos {
		if(repo.Hash == utils.SHARED_HASH){
			continue;
		}
		//utils.Debug("Repo.Name: ", repo.Name , "; hash: ", repo.Hash , "; local: ", repo.Local )
		f := FolderEx{}
		absPath, _ := filepath.Abs(repo.Local)
		f.absPath = filepath.Clean(absPath)
		f.relativePath = utils.ROOT_SHARE_NODE + "/" + repo.Name
		//f.parentHash = utils.HEAD_TEXT
		f.repo = repo
		f.hashSuffix = repo.HashSuffix;
		if len (repo.Includes) > 0 {
			tokens := strings.Split(repo.Includes, ",")
			for _, idx := range tokens {
				row := utils.GetRowAt(utils.GetTopTreeFolder()+"/"+utils.HashToPath(repo.Hash)+".bin", utils.ToUint32(idx))
				if (row == nil) {
					continue;
				}
				bs, err := utils.DbGetStringValue( row.FileNameKey, true);
				if (!err  ) {
					continue
				}
				f.files = append(f.files, string(bs))
			}
		}

		if(repo.ShareState == utils.REPO_SHARE_STATE_OWNER){
			var r string;
			p :=  utils.GetFolderFullRelativePath(repo.Hash, &r)
			f.relativePath = utils.ROOT_NODE + "/" + r + "/" + p;
			myShares = append(myShares, f)
		}else{
			if obj, ok := shared[repo.Owner]; ok {
				obj = append(obj, f)
				shared[repo.Owner] = obj;
			}else{
				var t []FolderEx;
				t = append(t, f)
				shared[repo.Owner] = t;
			}
		}
	}

	return fex, myShares, shared
}
func setupNewRepo(local string) []FolderEx {
	var fex []FolderEx

	fes, _, _ := repoToFolderEx()

	for _, f := range fes {
		if f.repo.Local == local {
			fex = append(fex, f)
			return fex
		}
	}
	return fex
}

//check if "p" is the parent folder of "folder"
//folder example  /home/data/test2    /home/data/sub1/sub2
//p example  /home/data/test   /home/data/sub1
func isParentFolder(folder, p string)bool{
	if(folder == p){
		return true;
	}
	if(! strings.HasPrefix(folder, p)){
		return false;
	}
	psize := len(p);
	fi := folder;
	for{
		d := filepath.Dir(fi);
		utils.Debug("Dir is ", d)
		if(d == p){
			return true;
		}
		if(len(d) < psize){
			return false;
		}
		fi = d;
	}
}

func foldersToFolderEx(folders []string, isNewRepo bool) ([]FolderEx,[]FolderEx, map[string][]FolderEx) {
	var myShares []FolderEx
	var fex []FolderEx

	if isNewRepo {
		local := filepath.Clean(folders[0])
		return setupNewRepo(local), nil, nil
	}

	s := make(map[string]bool)
	repos := utils.GetRepositoryList();
	shareRepos := utils.GetShareFolderList(repos)
	shared := make(map[string][]FolderEx);

	for _, folder := range folders {
		path := filepath.Clean(folder)
		if utils.SetContains(s, path) {
			continue
		}
		for _, share := range shareRepos {
			if(share.Local == path){
				f := FolderEx{}
				f.hash = share.Hash;
				f.absPath = path
				f.repo = share
				f.relativePath = utils.ROOT_SHARE_NODE + "/" + share.Name
				if(share.ShareState == utils.REPO_SHARE_STATE_OWNER){
					myShares = append(myShares, f)
				}else{
					if obj, ok := shared[share.Owner]; ok {
						obj = append(obj, f)
						shared[share.Owner] = obj;
					}else{
						var t []FolderEx;
						t = append(t, f)
						shared[share.Owner] = t;
					}
				}
				break;
			}
		}

		for _, repo := range repos {
			if repo.Local == "" {
				continue
			}
			absPath, _ := filepath.Abs(repo.Local)
			absPath = filepath.Clean(absPath)
			utils.Debug("path: ", path, "; abspath: ", absPath, "; repo: ", repo.Name)
			if isParentFolder(path, absPath) {
				utils.Debug("hasprefix. path: ", path)
				var sub []FolderEx
				for {
					f := FolderEx{}
					p := ""
					toExit := false
					n1 := len(path)
					n2 := len(absPath)
					if n1 == n2 {
						f.relativePath = utils.ROOT_NODE + "/" + repo.Name
						toExit = true
					} else if n1 > n2 {
						p = path[len(absPath):]
						f.relativePath = filepath.Clean(utils.ROOT_NODE + "/" + repo.Name + "/" + p)
					} else {
						toExit = true //something wrong, so exit to avoid infinite loop
					}

					f.hash = utils.GetFolderPathHash(f.relativePath)
					f.absPath = path
					f.repo = repo
					s[path] = true
					sub = append(sub, f)

					if toExit {
						break
					}
					binFile := utils.GetTopTreeFolder() + utils.HashToPath(f.hash) + ".bin"
					if !utils.FileExists(binFile) {
						path = utils.RemoveLastPathComponent(path)
						utils.Debug("BinFile does not exist: ", binFile, "; path: ", path)
					} else {
						utils.Debug("BinFile  exists: ", binFile)
						break
					}
				}
				fex = append(fex, reverse(sub)...)
				break
			}
		}

	}
	utils.Debug("Returns from foldersToFolderEx, fex: ", fex)
	return fex, myShares, shared
}

func reverse(s []FolderEx) []FolderEx {
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i]
	}
	return s
}

func toRepos(folders []FolderEx) string {
	repos := ""
	for _, f := range folders {
		if repos == "" {
			repos += "[" + f.repo.Name
		} else {
			repos += "," + f.repo.Name
		}
	}
	repos += "]"
	return repos
}

//check subdirectory of .AnySync to see if the email already exists in one of config files
func userExistsLocally(email string, password string) ([]byte, []byte,[]byte, []byte, string, string) {
	root := utils.GetAppRoot()
	dir, err := os.Open(root)
	if err != nil {
		return nil, nil, nil, nil, "", ""
	}
	defer dir.Close()
	fis, err := dir.Readdir(-1)
	if err != nil { //may be because there is no privilege
		return nil, nil, nil, nil, "", ""
	}
	for _, fileInfo := range fis {
		if !fileInfo.IsDir() {
			continue
		}
		//utils.Debug("dir: " , fileInfo.Name() )
		configFile := root + "/" + fileInfo.Name() + "/config"
		if utils.FileExists(configFile) {
			utils.Debug("Found config file: ", configFile)
			if conf, err := utils.LoadConfigFile(configFile); err == nil {
				utils.Debug("config file's user: ", conf.User)
				if conf.Email == email {
					utils.Debug("Found a local user")
					keyFile := root + "/" + fileInfo.Name() + "/data/" + utils.MASTER_KEY_FILE
					if m, err := utils.DecryptMasterKeys([]byte(password), keyFile); err != nil {
						return nil, nil, nil, nil, "", ""
					} else {
						utils.Debug("F master key file, accessToken: ", fmt.Sprintf("%x", m["acc"]), "; pubKey:", fmt.Sprintf("%x", m["pub"]) )
						return m["enc"], m["auth"], m["acc"], m["priv"], conf.User, conf.DeviceID
					}
				}
			}
		}
	}
	return nil, nil, nil, nil, "", ""
}

type FilterEx struct {
	Filter     *filter.Filter
	lastUpdate int64
	//RefTime time.Time;
}

var gFilter *FilterEx

func getFilterFromConfig() *FilterEx {
	if gFilter != nil {
		return gFilter
	}
	f, _ := filter.NewFilter(&filterflags.Opt)
	gFilter = &FilterEx{}
	gFilter.Filter = f

	config := utils.LoadConfig()
	//Rules are added in this order: Include, Exclude, Filter.
	hasAtleastOneInclude := false
	if config.Included != "" {
		hasAtleastOneInclude = addRules(gFilter.Filter, config.Included, true)
	}
	if config.Excluded != "" {
		addRules(gFilter.Filter, config.Excluded, false)
	}
	if config.MaxSize > 0 {
		gFilter.Filter.Opt.MaxSize = fs.SizeSuffix(config.MaxSize * 1024 * 1024 * 1024)
	}

	if hasAtleastOneInclude { //This adds an implicit --exclude * at the very end of the filter list.
		gFilter.Filter.Add(false, "*")
	}
	gFilter.update()
	return gFilter
}

func (f *FilterEx) update() {
	if time.Now().Unix()-f.lastUpdate < 2 {
		return
	}
	config := utils.LoadConfig()
	if config.MaxAge > 0 {
		duration := time.Duration(time.Duration(config.MaxAge) * 24 * time.Hour) // 600 seconds , err := ParseDuration(*maxAge)
		gFilter.Filter.ModTimeFrom = time.Now().Add(-duration)
	}
	if config.MinAge > 0 {
		duration := time.Duration(time.Duration(config.MinAge) * time.Second)
		fmt.Println("MinAge, duration: ", duration)
		gFilter.Filter.ModTimeTo = time.Now().Add(-duration)
	}
	f.lastUpdate = time.Now().Unix()
}

func addRules(filter *filter.Filter, text string, isInclude bool) bool {
	tokens := strings.Split(text, ",")
	hasAtleastOne := false
	for _, token := range tokens {
		token = strings.TrimSpace(token)
		if len(token) == 0 {
			continue
		}
		filter.Add(isInclude, token)
		hasAtleastOne = true
	}
	return hasAtleastOne
}

func (this *Rescan)  FilterFile(path string, file os.FileInfo) bool {
	if this.filter == nil {
		this.filter = getFilterFromConfig()
		this.filter.update()
	}
	b := this.filter.Filter.Include(path, file.Size(), file.ModTime())
	if !b {
		return false
	}
	return this.filter.Filter.Include(file.Name(), file.Size(), file.ModTime())
}

func  FilterFile(path string, file os.FileInfo) bool {
	filter := getFilterFromConfig()
	filter.update()
	b := filter.Filter.Include(path, file.Size(), file.ModTime())
	if !b {
		return false
	}
	return filter.Filter.Include(file.Name(), file.Size(), file.ModTime())
}

func createBucketIfNecessary()  {
	config := utils.LoadConfig()
	if(config.IsOfficialSite()){
		return;
	}

	p := utils.LoadAppParams()
	if(len(p.GetSelectedStorage().Bucket) > 0){
		return
	}
	b := p.RemoteNameCode + ":" + utils.DEFAULT_BUCKET; // p.GetSelectedStorage().Bucket
	utils.Info("createBucketIfNecessary. bucket:" , b)
	fdst := cmd.NewFsDir([]string{b})
	if err := fdst.Mkdir(context.Background(), ""); err == nil {
		p.GetSelectedStorage().Bucket = utils.DEFAULT_BUCKET;
		if p.Save() == nil {
			utils.CurrentParams = p;
		}
	}
}

func removeSelectedFolders(folder string, fis []os.FileInfo) []os.FileInfo{
	config := utils.LoadConfig();
	if !config.HasSelectedFolder() {
		return fis
	}
	folder = folder[len(utils.ROOT_NODE) + 1 : ]
	var ret [] os.FileInfo
	for _, f := range fis {
		key :=  folder + "/" + f.Name()
		if config.IsSelectedFolder(key) {
			continue;
		}
		ret = append(ret, f)
	}

	return ret;
}
