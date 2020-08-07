// Copyright (c) 2020, Yanbin (Henry) Zheng <ybzheng@gmail.com>
// All rights reserved.
//
// Use of this source code is governed by a AGPLv3 license that can be
// found in the LICENSE file.
package client

import (
	"fmt"
	"github.com/golang/protobuf/proto"
	"strings"
	"time"
	utils "github.com/anysync/server/utils"
)

var TASKS_STRING = [...]string{"update row", "create bin", "write bin", "append bin", "delete file", "add filename", "update local"}

func createFolderBinFile(row []byte, repoHash, parentHash, fileNameKey, fileName,  repoTree string) *utils.WriteTask{
	var io utils.IndexBinRow;
	io.ReadBytes(row, 0)
	if (utils.IsFileModeDirectory(io.FileMode)) {
		hash := io.ToHashString();
		binFile := repoTree + utils.HashToPath(hash) +".bin";
		if(!utils.FileExists(binFile)){
			utils.Debug("utils.TASK_UPDATE_ROW. To add CreateBinTask for folder: ", hash, "; nameKey: " , fileNameKey, "; its parent hash:", parentHash, "; binFile:", binFile)
			t,_ := CreateBinTask(repoHash, hash, parentHash, fileNameKey, fileName);
			//ExecuteTask(t, true, repo, user)
			return t;
		}
	}
	return nil;
}
func CreateUpdateRowTask( taskList *[]*utils.WriteTask, repoHash, folderHash string, index uint32, bs []byte, attribs map[string][]byte, fileNameKey, fileName, suffix , repoTree string) *utils.WriteTask {
	task := utils.NewWriteTask(folderHash, utils.TASK_UPDATE_ROW)
	task.Index = index
	task.Bytes = bs // CopyBytes(row.Row);
	task.Data = fileName;
	task.FileHash = suffix;
	if attribs != nil && len(attribs) > 0 {
		task.Attribs = attribs
	}

	if taskList != nil {
		//if !taskExists(taskList, task) {
			*taskList = append(*taskList, task)
			if t := createFolderBinFile(task.Bytes, repoHash, folderHash, fileNameKey, fileName, repoTree); t != nil {
				utils.Debug("UpdateRow. Add createFolderRow task: ", t)
				*taskList = append(*taskList, t)
			}
		//}
	}

	return task
}

func taskExists(taskList *[]*utils.WriteTask, task * utils.WriteTask)bool{
	for _, t := range *taskList {
		if t.Mode != task.Mode || t.Index != task.Index || t.FolderHash != task.FolderHash{
			continue
		}
		if t.Mode == utils.TASK_UPDATE_ROW || t.Mode == utils.TASK_WRITE_BIN || t.Mode == utils.TASK_CREATE_BIN {
			if  BytesEqual(t.Bytes, task.Bytes) {
				utils.Debug("Task exists:", t.FolderHash, "; mode:", task.Mode)
				return true
			}
		}
	}

	return false
}

// Equal tells whether a and b contain the same elements.
// A nil argument is equivalent to an empty slice.
func BytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i, v := range a {
		if v != b[i] {
			return false
		}
	}
	return true
}

func CreateAddFileNameTask(folderHash string, content string) *utils.WriteTask {
	//utils.Debugf("CreateAddFileNameTask, folderHash:%s, content: %s", folderHash, content)
	task := utils.NewWriteTask(folderHash, utils.TASK_ADD_FILE_NAME)
	task.Data = content
	return task
}


func CreateCopyBinTask(fileHash, oldFileHash, fileNameKey string) *utils.WriteTask{
	task := utils.NewWriteTask(fileHash, utils.TASK_COPY_BIN)
	task.FileHash = oldFileHash;
	task.Data = fileNameKey
	return task;
}

func CreateDeleteFileTask(folderHash string, fileHash string, rowIndex uint32) *utils.WriteTask {
	task := utils.NewWriteTask(folderHash, utils.TASK_DELETE_FILE)
	task.FileHash = fileHash
	task.Index = rowIndex
	return task
}

func CreateBinTask(repoHash, folderHash string, parentHash, fileNameKey, fileName string) (*utils.WriteTask, *utils.WriteTask) {
	task := utils.NewWriteTask(folderHash, utils.TASK_CREATE_BIN)
	utils.Debug("++++++++++++++++++++ CreateBin, folderHash: ", folderHash, "; parentHash: ", parentHash, "; \nnamekey: ", fileNameKey, "; fileName:", fileName)
	key:= utils.NULL_FILE_KEY;
	var addNameTask *utils.WriteTask;
	if(fileNameKey != "" && folderHash != utils.NULL_HASH) {
		//key = CalculateFileNameKey(fileName, true, parentHash, suffix)
			key = fileNameKey
			addNameTask = CreateAddFileNameTask(parentHash, CreateRow(key, fileName));
	}
	firstRow := createFolderRow(repoHash, parentHash, key)
	task.Bytes = firstRow

	return task, addNameTask
}

func createWriteBinTask(folderHash string, newRowBytes []byte) *utils.WriteTask {
	task := utils.NewWriteTask(folderHash, utils.TASK_WRITE_BIN)
	task.Bytes = newRowBytes ; //CopyBytes(newRowBytes)
	return task
}

/*
The fileName and fileNameKey are required if the passed newRowBytes is a folder row.
 */
func CreateAppendBinRowTask(taskList *[]*utils.WriteTask, repoHash, folderHash string, index uint32, newRowBytes []byte, attribs map[string][]byte, fileNameKey, fileName,  repoTree string) (*utils.WriteTask, *utils.WriteTask) {
	task := utils.NewWriteTask(folderHash, utils.TASK_APPEND_BIN)
	task.Bytes = newRowBytes // CopyBytes(newRowBytes);
	task.Index = index
	//task.FileHash = suffix;
	task.Data = fileName
	if attribs != nil && len(attribs) > 0 {
		task.Attribs = attribs
	}

	var folderTask * utils.WriteTask;
	if taskList != nil  {
		*taskList = append(*taskList, task)
		//If the passed newRowBytes is a folder, then create the folder bin file too, otherwise createFolderBinFile does nothing.
		if len(fileNameKey) > 0 {
			if folderTask = createFolderBinFile(task.Bytes, repoHash, folderHash, fileNameKey, fileName, repoTree); folderTask != nil {
				utils.Debug("AppendBin. Add createFolderRow task: ", folderTask)
				*taskList = append(*taskList, folderTask)
			}
		}
	}

	return task, folderTask
}

func CreateUpdateLocalCopyTask(folderHash, fileHash string, rowIndex uint32, fileMode uint32, isSizeZero bool) *utils.WriteTask {
	task := utils.NewWriteTask(folderHash, utils.TASK_UPDATE_LOCAL)
	task.Side = utils.SIDE_CLIENT_ONLY
	task.FileHash = fileHash
	task.Index = rowIndex
	task.Data = fmt.Sprintf("%d,%v", fileMode,isSizeZero)
	return task
}

func ExecuteTasks(tasks []*utils.WriteTask, isClientSide bool,  user string) {
	if(isClientSide){
		user = ""
	}
	for _, task := range tasks {
		ExecuteTask(task, isClientSide,  user, false)
	}
}

func handleTaskAttribs(task *utils.WriteTask,isClientSide bool,  user string, skipCheckShare bool){
	if task.Attribs != nil && len(task.Attribs) > 0 {
		utils.UpdateAttribs(isClientSide, user, task.FolderHash, task.Index, task.Attribs)
		if(isClientSide && !skipCheckShare && task.FolderHash == utils.SHARED_HASH){
			utils.Debug("TASK_APPEND_BIN. task.attrib[hash]:", task.Attribs["hash"])
			CallShareFolderInit( task.Attribs);
		}
	}
}

func ExecuteTask(task *utils.WriteTask, isClientSide bool,  user string, skipCheckShare bool)  *utils.WriteTask{
	var repo string
	if(user != ""){
		repo = utils.GetUserRootOnServer(user)
	}else{
		repo = utils.GetAppHome()
	}
	repoTreePath := repo + "/tree/"
	var newTask  *utils.WriteTask;
	if (isClientSide && task.Side == utils.SIDE_SERVER_ONLY) || (!isClientSide && task.Side == utils.SIDE_CLIENT_ONLY) {
		return nil
	}
	var subPath, base, binFileName string;
	if len(task.FolderHash) > 0 {
		subPath = utils.HashToPath(task.FolderHash)
		base = repoTreePath + subPath
		binFileName = base + ".bin"
	}
	//utils.Debug("To execute task on ", side , ", Mode:",  getTaskModeString(task.Mode) , " - ", task.Mode, ". Index:", task.Index, "; FolderHash: ", task.FolderHash)
	switch task.Mode {
	case utils.TASK_UPDATE_ROW:
		if len(task.Bytes)%utils.FILE_INFO_BYTE_COUNT != 0 {
			utils.Debugf("Error3, append row Bytes.len: %d\n", len(task.Bytes))
		}
		if(task.Bytes != nil) {
			//utils.Debugf("UpdateRow, index:%d, hash:%s, size: %d, row: %s\n", task.Index, task.FolderHashFolderHash, utils.FileSize(binFileName), hex.EncodeToString(task.Bytes))
			updateRowAtWithBytes(base, task.Index, task.Bytes, true)
		}
		if task.Attribs != nil && len(task.Attribs) > 0 {
			utils.Debug(("UpdateRow: update attribs..."))
			utils.UpdateAttribs(isClientSide, user, task.FolderHash, task.Index, task.Attribs)
		}

	case utils.TASK_WRITE_BIN://used in deleted files
		WriteAndAppendLog( base, task.Bytes, 0, true, false)
	case utils.TASK_CREATE_BIN:
		if !utils.FileExists(binFileName) {
			if len(task.Bytes)%utils.FILE_INFO_BYTE_COUNT != 0 {
				utils.Debugf("Error2, append row Bytes.len: %d", len(task.Bytes))
			}
			WriteAndAppendLog( base, task.Bytes, 0, true, false)
		}
	case utils.TASK_APPEND_BIN: //append row to .bin file
		WriteAndAppendLog( base, task.Bytes, 0, false, true)
		handleTaskAttribs(task, isClientSide, user, skipCheckShare)
	case utils.TASK_COPY_BIN:
		var binDir string;
		if isClientSide {
			binDir =utils.GetTopTreeFolder();
		}else{
			binDir = utils.GetUserRootOnServer(user) + "/tree/"
		}
		utils.Debug("To copybin, src:", binDir + utils.HashToPath(task.FileHash) + utils.EXT_BIN, "; dest:" , binDir + utils.HashToPath(task.FolderHash) + utils.EXT_BIN)
		newbinFile := binDir + utils.HashToPath(task.FolderHash) + utils.EXT_BIN;
		utils.CopyFile( binDir + utils.HashToPath(task.FileHash) + utils.EXT_BIN, newbinFile)
		utils.CopyFile( binDir + utils.HashToPath(task.FileHash) + utils.EXT_LOG, binDir + utils.HashToPath(task.FolderHash) + utils.EXT_LOG)
		updateFileNameKeyAt(newbinFile, 0, task.Data)
	case utils.TASK_ADD_FILE_NAME:
		line := task.Data
		pos := strings.Index(line, "=")
		if(pos > 0) {
			name := line[0:pos]
			value := line[pos+1:]
			utils.Debug("utils.TASK_ADD_FILE_NAME. user:", user, "; name: ", name, ", value: ", value)
			if isClientSide {
				utils.NamesDbSetStringValue(name, value)
			} else {
				utils.ServerNamesDbSetStringValue(user, name, value)
			}
		}

	case utils.TASK_DELETE_FILE:
		if(isClientSide) {
			utils.Debugf("Enter utils.TASK_DELETE_FILE, fileHash:%s\n", task.FileHash)
			deleteLocalCopy(repoTreePath, task.FolderHash, task.FileHash, task.Index)
		}
	case utils.TASK_UPDATE_LOCAL:
		if task.FileHash != utils.NULL_HASH {
			baseFileName := repoTreePath + utils.HashToPath(task.FolderHash)
			tokens := strings.Split(task.Data, ",");
			fileMode := utils.ToUint32(tokens[0]);// == "true";
			isSizeZero := tokens[1] == "true";
			updateLocalCopy(task.FolderHash, baseFileName + ".bin", task.FileHash, task.Index, utils.IsFileModeDirectory(fileMode), utils.IsFileModeDeleted(fileMode), isSizeZero)
		}
	}
	return newTask
}

func checkUpdateDat() bool {
	if utils.FileExists(utils.GetUpdateDatTasksFolder()) {
		bytes, err := utils.Read(utils.GetUpdateDatTasksFolder())
		if err != nil {
			utils.RemoveFile(utils.GetUpdateDatTasksFolder())
		} else {
			tasksObj := utils.UpdateDatTask{}
			if proto.Unmarshal(bytes, &tasksObj) == nil {
				updateDatFilesAndCloseGap(tasksObj.Objects, tasksObj.FolderUpdates)
			}
			utils.RemoveFile(utils.GetUpdateDatTasksFolder())
		}
	}
	if utils.FileExists(utils.GetUpdateDatTasksFolder()) {
		return false
	}
	return true
}
func SaveUpdateDatTaskCommit( fileName string, objects map[string][]byte, folderUpdates map[string]*utils.ServerFolderUpdates, shareState int32) {
	tasks := utils.UpdateDatTask{}
	tasks.Time = uint32(time.Now().Unix())
	tasks.Objects = objects
	tasks.FolderUpdates = folderUpdates
	tasks.ShareState = shareState;
	bytes, err := proto.Marshal(&tasks)
	if err != nil {
		return
	}
	utils.WriteBytesSafe(fileName, bytes)
}

func saveUploadStagingTask(  msg * utils.ModifiedData, shareState int32, owner string) {
	utils.Debug("Enter saveUploadStagingTask")
	defer utils.Debug("Leave saveUploadStagingTask");
	fileName := utils.GetFolder("tasks") + utils.UPLOAD_STAGING
	tasks := utils.UploadStagingTask{}
	tasks.ShareState = shareState;
	tasks.Msg =  msg;
	tasks.Owner = owner
	bytes, err := proto.Marshal(&tasks)
	if err != nil {
		return
	}
	utils.WriteBytesSafe(fileName, bytes)
}

func removeUploadStagingTask(){
	utils.Debug("Enter removeUploadStagingTask")
	defer utils.Debug("Leave removeUploadStagingTask");
	taskFolder :=  utils.GetTasksFolder();
	fileName :=taskFolder + utils.UPLOAD_STAGING
	utils.RemoveFile(fileName)

	//utils.RemoveAllSubItems(taskFolder) //remove task db
}

func checkUploadStaging() bool {
	filename := utils.GetFolder("tasks") + utils.UPLOAD_STAGING

	if utils.FileExists(filename) {
		bytes, err := utils.Read(filename)
		if err != nil {
			utils.RemoveFile(utils.GetUpdateDatTasksFolder())
		} else {
			rescan := new(Rescan)
			tasksObj := utils.UploadStagingTask{}
			rescan.shareState = tasksObj.ShareState
			rescan.owner = tasksObj.Owner;
			if proto.Unmarshal(bytes, &tasksObj) == nil {
				if _, b := rescan.uploadStagingAndSendout(tasksObj.Msg, false); b > 0{
					return false;
				}else{
					StartRescan(nil)
				}
			}
		}
	}
	return true
}

func checkResetAllTask() bool {
	if utils.FileExists(utils.GetResetAllTasksFolder()) {
		bytes, err := utils.Read(utils.GetResetAllTasksFolder())
		if err != nil {
			utils.RemoveFile(utils.GetResetAllTasksFolder())
			return true
		} else {
			tasksObj := utils.WriteTask{}
			if proto.Unmarshal(bytes, &tasksObj) == nil {
				now := uint32(time.Now().Unix())
				if (now - tasksObj.Time) > uint32(86400*15) { //too old, delete it.
					utils.RemoveFile(utils.GetResetAllTasksFolder())
					return true
				}
				if err = utils.ExecuteResetAll(&tasksObj); err == nil {
					utils.RemoveFile(utils.GetResetAllTasksFolder())
					return true
				} else {
					return false
				}
			}
		}
	}
	return true
}

//Finish any incomplete client side tasks.
func HandleIncompleteTasks() {
	scanMutex.Lock()
	defer 	scanMutex.Unlock()
	utils.Debug("Enter HandleIncompleteTasks")
	checkUploadStaging()
	checkUpdateDat()
	checkResetAllTask()
	checkRemainingTasks()
	checkRemainingDownloads()
	//utils.RemoveAllSubItems(utils.GetTasksFolder())
}

func checkRemainingTasks() bool{
	utils.Debug("Enter checkRemainingTasks")
	db := utils.NewDb(utils.GetTasksFolder() + "/data.db")
	if db == nil {
		return true;
	}
	var ts []*utils.WriteTask;
	utils.DbIterate(db, "", func(key []byte, value []byte) bool {
		tasksObj := new(utils.WriteTask)
		if proto.Unmarshal(value, tasksObj) == nil {
			ts = append(ts, tasksObj)
		}
		return true
	})
	db.Close()
	if len(ts) > 0 {
		ExecuteClientSideTasks(ts);
	}
	return true;
}

func checkRemainingDownloads()bool{
	utils.Debug("Enter checkRemainingDownloads")
	db := utils.NewDownloadDb()
	if db == nil {
		return true;
	}
	defer db.Close()

	var deletes []string;

	utils.DbIterate(db, "", func(key []byte, value []byte) bool {
		tokens := strings.Split(string(key), "|")
		folderHash := tokens[0]
		fileHash := tokens[1]
		tokens = strings.Split(string(value), ",")
		hasNew := false;
		if tokens[0] == "1" {
			hasNew = true;
		}
		rowIndex := utils.ToUint32(tokens[1])
		fileMode := utils.ToUint32(tokens[2])
		opMode := uint8(utils.ToUint32(tokens[3]))
		fileSize, _ := utils.ToInt64(tokens[4])
		if updateLocalFile(folderHash, fileHash, hasNew, rowIndex, fileMode, opMode, fileSize, "", nil) {
			deletes = append(deletes, folderHash + fileHash)
			//b.Delete([]byte(folderHash + fileHash))
		}
		return true
	})
	utils.DeleteTasks(db, deletes)

	return true;
}
