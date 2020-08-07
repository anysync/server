// Copyright (c) 2020, Yanbin (Henry) Zheng <ybzheng@gmail.com>
// All rights reserved.
//
// Use of this source code is governed by a AGPLv3 license that can be
// found in the LICENSE file.

package server

import (
	"bytes"
	client "github.com/anysync/server/client"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/golang/protobuf/proto"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
	utils "github.com/anysync/server/utils"
)
const(
	USER_INIT_QUOTA = 50;
	FIRST_ID = 1170367;
)




func PrintTimeCost(t1 int64, functionName string) {
	t2 := time.Now().Unix()
	utils.Debug(functionName, " spent ", (t2 - t1), "; t1:", time.Unix(t1, 0), "; t2:", time.Unix(t2, 0))
}

//One UserID can have one or more deviceID.
func ProcessAtRemoteServer(user, originator string, deviceIDi uint32, headers map[string]string, clientChanges []*utils.ModifiedFolder) (utils.ServerSyncResponse, *ServerBinLog) {
	deviceID := fmt.Sprintf("%d", deviceIDi)
	userRoot := utils.GetUserRootOnServer(user)
	defer utils.TimeTrack(time.Now(), "ProcessAtRemoteServer")
	end := (0)
	if s, ok := headers["size"]; ok {
		utils.Debug("Found 'size' in headers: ", s, "; deviceID: ", deviceIDi)
		end = utils.ToInt(s)
	} else {
		utils.Debug("Not found 'size' in headers; deviceID: ", deviceIDi, ". So use binFileSize: ", end)
	}

	var binLog = NewServerBinLog(user, deviceID, end)
	binLog.suffix = headers["suffix"]
	binLog.folderRoot = make(map[string]string)

	


	if originator == "" { //if originator is not empty, then the request is from a non-owner share folder, so don't check main bin file. //shareState != utils.REPO_SHARE_STATE_SHARE){
		binLogFile := userRoot + "/data/server.bin"
		binLog.BinFileName = binLogFile
		if end == 0 {
			end = int(utils.FileSize(binLogFile))
		}
		fileOffsetOnServer, fileSize := utils.GetClientDatOffset(user, deviceID, "")
		utils.Debug("called GetClientDatOffset3. user:", user, "; offset:", fileOffsetOnServer, "; fileSize:", fileSize)
		if val, ok := headers["offset"]; ok { //if client's request has offset info, use it instead.
			utils.Debug("Header.offset: ", val, "; device: ", deviceID)
			o, _ := strconv.Atoi(val)
			fileOffsetOnServer = uint32(o)
		}
		if fileSize == 0 || fileOffsetOnServer < fileSize {
			binLog.readLogSince(userRoot + "/tree/", fileOffsetOnServer, end, nil)
		}
	}
	if binLog.FolderUpdates == nil {
		utils.Debug("before merge. FolderUpdates is nil.")
		binLog.FolderUpdates = make(map[string]*utils.ServerFolderUpdates)
	}
	objects := make(map[string][]byte)
	code := int32(0)
	if !binLog.merge(clientChanges) {
		utils.Debug("Set code to SERVER_CHANGE_TOO_MANY")
		code = utils.SERVER_CHANGE_TOO_MANY
	}else {
		binLog.collectChanges()

		i := 0
		for _, change := range binLog.serverChanges {
			root := userRoot
			u := user;
			utils.Debug("here.change.FolderHash: ", change.FolderHash)
			if value, ok := binLog.folderRoot[change.FolderHash]; ok {
				root = utils.GetUserRootOnServer(value)
				u = value;
			}
			for _, row := range change.Rows {
				client.AddObjectByFileHash(u, root, row.GetIndexBinRow().ToHashString(), row.OperationMode, objects)
			}
			i++
		}
	}
	props := make(map[string]string)
	return utils.ServerSyncResponse{Props: props, FolderUpdates: binLog.FolderUpdates, Tasks: binLog.WriteTasks, TaskTopFolder: userRoot, Objects: objects, Code: code}, binLog
}




type ServerBinLog struct {
	currentTimestamp uint32
	BinFileName      string //"$SERVER_HOME/data/server.bin"
	DeviceID         string
	User             string
	FolderUpdates    map[string]*utils.ServerFolderUpdates
	serverChanges    map[string]*utils.ModifiedFolder
	clientChanges    []*utils.ModifiedFolder
	objects          map[string]string
	folderRoot       map[string]string
	conflicts        map[string][]uint32
	suffix           string
	end              int
	//CanWriteToDisk   bool;
	WriteTasks []*utils.WriteTask
	shareState int32
}

func NewServerBinLog(user, deviceID string, end int) *ServerBinLog {
	var binLog = ServerBinLog{DeviceID: deviceID, User: user, end: end}
	binLog.serverChanges = make(map[string]*utils.ModifiedFolder)
	binLog.FolderUpdates = make(map[string]*utils.ServerFolderUpdates)
	return &binLog
}

//save the size info to server.bin
func UpdateServerBinTasks(taskList []*utils.WriteTask, userID string, prevSizes map[string]int64, shareState int32) map[string]int64 {
	folders := make(map[string]int64)
	utils.Debug("Enter UpdateServerBinTasks. Tasks.size:", len(taskList))
	for _, task := range taskList {
		//utils.Debug("~~~ task.mode:", task.Mode, ";folder:", task.FolderHash)
		//if(task.Mode == TASK_CREATE_BIN || task.Mode == TASK_WRITE_BIN || task.Mode == TASK_CREATE_BIN || task.Mode == TASK_APPEND_BIN){
		if task.Mode != utils.TASK_UPDATE_LOCAL && len(task.FolderHash) > 0 {
			if _, ok := folders[task.FolderHash]; !ok {
				folders[task.FolderHash] = 0
			}
		}
	}

	//UpdateServerBinForFolders(  folders, userID, "", prevSizes, shareState)

	if shareState == utils.REPO_SHARE_STATE_SHARE {
		utils.Debug("UpdateServerBinTasks, state is share")
		UpdateServerBinForFolders(folders, userID, "", prevSizes, shareState)
		//UpdateServerBinForFolders(folders, userID, utils.GetUserRootOnServer(userID)+"/data/server", prevSizes, shareState)
	} else if shareState == utils.REPO_SHARE_STATE_OWNER {
		utils.Debug("UpdateServerBinTasks, state is owner")
		UpdateServerBinForFolders(folders, userID, "", prevSizes, shareState)
		//UpdateServerBinForFolders(  folders, userID, utils.GetUserRootOnServer(userID) + "/data/server", prevSizes, shareState)
	} else if shareState == utils.REPO_SHARE_STATE_ALL {
		UpdateServerBinForFolders(folders, userID, utils.GetUserRootOnServer(userID)+"/data/server", prevSizes, shareState)
	}

	utils.Debug("before returning from  UpdateServerBinTasks, folders:", folders)
	return folders
}

func UpdateServerBinForFolders(folders map[string]int64, user, base string, prevSizes map[string]int64, shareState int32) {
	var logWriter *utils.BinIO
	if len(base) > 0 {
		logWriter = utils.NewBinIO(base, utils.BIN_TYPE_SERVER_BIN)
	}
	utils.Debug("folderHash.size: ", len(folders), "; shareState: ", shareState, "; base:", base)
	for folderHash := range folders {
		//utils.Debug("UpdateServerBinForFolders. Folder:", folderHash)
		subPath := utils.HashToPath(folderHash)
		

		if base == "" {
			

		} else {
			repo := utils.GetUserRootOnServer(user)
			

			repoTree := repo + "/tree/"
			pathLog := repoTree + subPath + ".log"
			var logFileSize int64 = 0
			var prevSize int64 = 0
			if utils.FileExists(pathLog) {
				logFileSize = utils.FileSize(pathLog)
			}
			if s, found := prevSizes[folderHash]; found {
				prevSize = s
			}
			//utils.Debug("logFileSize: ", logFileSize, "; prevSize: ", prevSize, "; server.bin: ", logWriter.Base)
			if logFileSize > prevSize {
				dir := filepath.Dir(logWriter.Base)
				if !utils.FileExists(dir) {
					utils.MkdirAll(dir)
				}
				data := appendToArray(repoTree, int(prevSize), folderHash, int(logFileSize))
				logWriter.Append(data)
				s := utils.FileSize(base + ".bin")
				folders[folderHash] = s
				//utils.Debug("~~~~~~~~~~~~~~~~~~~~~~~~~ To append data to server.bin, data.len: ", len(data), "; folderHash: ", folderHash, "; after-bin.size: ", s)
			}
		}
	}
}

var fileMutex = utils.NewKmutext() // &sync.Mutex{}

//Save clients.dat file
//base: such as utils.GetUserRootOnServer(userID) + "/data/"
func SaveClientsDatFile(userID, deviceID string, end int, shareFolderID string, fileSize int64, addSyncLine bool) {
	utils.Debug("Enter SaveClientsDatFile", "; user:", userID, "; device:", deviceID, "; end:", end, "; shareID:", shareFolderID, "; fileSize:", fileSize)
	sizeText := fmt.Sprintf("%d", fileSize)
	//if(shareOwner != userID){
	//	u, _ := GetUserAccountBy(userID, true);
	//	o, _ := GetUserAccountBy(shareOwner, true);
	//	if (u != nil && o !=nil && u.Server != o.Server) {
	//		data := make(map[string][]byte);
	//		data["device"] = []byte(deviceID); // []byte(fmt.Sprintf("%d", deviceID))
	//		data["end"] = []byte(fmt.Sprintf("%d", end))
	//		data["id"] = []byte(shareFolderID);
	//		data["size"] = []byte(sizeText)
	//		//data["shareOwner"] = []byte(shareOwner);
	//		if(addSyncLine) {
	//			data["sync"] = []byte("true")
	//		}
	//		utils.Debug("In SaveClientsDatFile. user:", u.Name, "; id:", u.ID, "; u.server:", u.Server, ";data:", data)
	//		if _, err := InvokeServerAction(u.Server, userID, "saveClientsDatFile", nil, data, nil, nil); err != nil {
	//			utils.Debug("Error occurred in saveClientsDatFile")
	//		} else {
	//			utils.Debug("SaveClientsDataFile on shareOwner's server:", shareOwner, "; user is ", userID)
	//		}
	//		return;
	//	}
	//}

	var base string
	if shareFolderID == "" {
		base = utils.GetUserRootOnServer(userID) + "/data/"
	} else {
		

	}
	fileMutex.Lock(userID)
	defer fileMutex.Unlock(userID)
	serverLogFileName := base + "server.bin"
	//update data/clients file
	if end == 0 {
		end = int(utils.FileSize(serverLogFileName))
		if end == 0 {
			end = int(fileSize)
		}
	}
	clientsData := base + utils.CLIENTS_DAT_FILE // "clients.dat"
	data, _ := utils.LoadFile(clientsData, utils.UTF8)
	changed := false
	ti := uint32(time.Now().Unix())
	if deviceID != "-1" {
		newLine := fmt.Sprintf("%d,%d", ti, end)
		data.Set("sync."+deviceID, newLine)
		utils.Debug("newLine:", newLine, "; deviceID:", deviceID)
		changed = true
	}
	if sizeText != "" && sizeText != "0" {
		data.Set("size", sizeText)
		changed = true
	}
	if addSyncLine && deviceID != "-1" {
		utils.Debug("Add Sync Line")
		newLine := fmt.Sprintf("%d,%s", ti, sizeText)
		data.Set("sync."+deviceID, newLine)
		utils.Debug("newLine:", newLine, "; deviceID:", deviceID)
		changed = true
	}
	if changed {
		utils.Debug("In saving clients.dat: ", clientsData, "; deviceID: ", deviceID, "; binFileSize:", sizeText)
		if !utils.FileExists(base) {
			utils.MkdirAll(base)
		}
		data.Save(clientsData)
	}
}

func (this *ServerBinLog) readLogSince(repoTree string, fileOffset uint32, fileEnd int, shareFolder *utils.ShareFolder) bool {
	utils.Debug("Enter readLogSince. BinFileName:", this.BinFileName)
	if shareFolder != nil && shareFolder.Owner != this.User {
		utils.Debug("To call readLogSinceOnOwner. repoTree:", repoTree, "; owner:", shareFolder.Owner, "; fileOffset:", fileOffset, "; fileEnd:", fileEnd)
		this.readLogSinceOnOwner(repoTree, fileOffset, shareFolder)
		return true
	}
	if !utils.FileExists(this.BinFileName) {
		utils.Debug("bin file does not exist:", this.BinFileName)
		return true
	}
	file, err := os.Open(this.BinFileName)
	if err != nil {
		utils.Debug("readLogSince returns false 1")
		return false
	}
	defer file.Close()
	if fileEnd == 0 {
		fileEnd = int(utils.FileSize(this.BinFileName))
	}

	utils.Debugf("readLogSince. binLogName:%s, Offset: %d, End: %d", this.BinFileName, fileOffset, fileEnd)
	if fileOffset > 0 {
		file.Seek(int64(fileOffset), 0)
	}
	rowCount := int((fileEnd - int(fileOffset)) / utils.SERVER_LOG_BIN_ROW_SIZE)
	if rowCount == 0 {
		return true
	}
	rowIndex := 0
	readCount := 0
	for {
		buf := make([]byte, utils.SERVER_LOG_BIN_ROW_SIZE*512)
		readCount, err = file.Read(buf)
		if err != nil || readCount == 0 {
			break
		}
		toExit := false
		start := 0
		for start < readCount {
			var s = buf[start : start+4]
			begin := binary.BigEndian.Uint32(s) //id
			start += 4

			s = buf[start : start+4]
			_ = binary.BigEndian.Uint32(s) //Timestamp
			start += 4

			s = buf[start : start+4]
			end := binary.BigEndian.Uint32(s)
			start += 4

			hash := buf[start : start+utils.HASH_BYTE_COUNT]
			sha := fmt.Sprintf("%x", hash)
			utils.Debug("readLogSince, hash:", sha, "; this.serverChanges:", this.serverChanges)
			if f, exists := this.serverChanges[sha]; !exists {
				var mfolder = utils.NewModifiedFolder()
				mfolder.FolderHash = sha
				mfolder.Offset = begin
				mfolder.End = end

				binFileName := repoTree + utils.HashToPath(sha) + ".bin"
				//binFileName := utils.GetUserRootOnServer(this.User) + "/tree/" + utils.HashToPath(sha)  + ".bin"
				repoHash := utils.GetRepoHashFromBinFile(binFileName)
				if repoHash == "" {
					continue
				}
				this.serverChanges[sha] = mfolder
				this.FolderUpdates[sha] = NewServerFolderUpdates(repoHash, sha)
				utils.Debug("rowIndex: ", rowIndex, "; ReadLog for  hash: ", sha, "; rowCount:", rowCount, "; repoHash: ", repoHash)
			} else {
				f.End = end
				this.serverChanges[sha] = f
				utils.Debug("insert to serverChanages, hash:", sha, " f:", f)
			}
			rowIndex++
			start += utils.HASH_BYTE_COUNT
			if rowIndex >= rowCount {
				toExit = true
				break
			}
			//Index += SERVER_LOG_BIN_ROW_SIZE;
		}
		if toExit {
			break
		}
	}
	return true
}

func (this *ServerBinLog) merge(changesFromClient []*utils.ModifiedFolder) bool {
	//conflict := false;
	var conflicts map[string][]uint32
	conflicts = make(map[string][]uint32)
	var newServerChangeRows []*utils.ModifiedRow //QList<QSharedPointer<utils.ModifiedRow>>
	rowCount := 0
	for serverKey, serverFolder := range this.serverChanges {
		newServerChangeRows = nil
		owner := this.User
		if val, ok := this.folderRoot[serverFolder.FolderHash]; ok {
			owner = val
		}
		utils.Debug("merge, serverFolder:", serverFolder.FolderHash, "; owner:", owner, "; this.FolderUpdates.len:", len(this.FolderUpdates))

		if _, b := this.loadRowsFromLogFile(serverFolder, owner, this.FolderUpdates[serverFolder.FolderHash], &rowCount); !b {
			if rowCount >= utils.MAX_CHANGE_COUNT_SERVER {
				utils.Debug("RowCount:", rowCount)
				return false;
			}
			continue
		}
		//printFolder("After loadRowsFromLog", serverFolder)
		for _, sr := range serverFolder.Rows {
			opMode := sr.GetOpMode()
			utils.Debug("index:", sr.GetRowIndex(), "; sr.fileKey: ", sr.GetRowFileNameKey(), " opMode: ", opMode, "; fileHash: ", sr.GetIndexBinRow().ToHashString())
			if opMode == utils.MODE_DELETED_DIRECTORY {
				if isFolderContainedOrParent(changesFromClient, sr.GetIndexBinRow().ToHashString()) {
					//a directory (e.g. dir1) was just removed on the server by client1; client2 still has dir1, and just changed a file in dir1 and sync. So the result should be dir1 is reinstated.

					//delete(serverFolder.Rows, si);
					sr.Conflict = utils.CONFLICT_REINSTATE_DIRECTORY
					sr.OperationMode = utils.MODE_UNKNOWN
					newServerChangeRows = append(newServerChangeRows, sr)
					continue
				}
			}
		}
		if clientFolder := containsFolder(changesFromClient, serverFolder.FolderHash); clientFolder != nil {
			clientRows := clientFolder.Rows
			fileNameMap := make(map[string]*utils.ModifiedRow)
			utils.FillMap(serverFolder, fileNameMap)
			utils.Debugf("Reach here. clientRows.len: %d. serverFolder:%s . rows.Size:%d\n", len(clientRows), serverFolder.FolderHash, len(serverFolder.Rows))
			for _, clientRow := range clientRows {
				index := clientRow.GetRowIndex()
				utils.Debugf("hindex:%d NameKey:%s, opMode:%d; fileNameMap.len:%d\n", index, clientRow.GetRowFileNameKey(), clientRow.OperationMode, len(fileNameMap))
				if sRow, ok := fileNameMap[clientRow.GetRowFileNameKey()]; ok {
					ioRow := sRow.GetIndexBinRow()
					utils.Debugf("Index: %d, NameKey: %s, sRow.Index: %d\n", index, clientRow.GetRowFileNameKey(), sRow.GetRowIndex())
					if utils.IsFileModeDeleted(ioRow.FileMode) {
						sRow.OperationMode = utils.MODE_REINSTATE_FILE
						continue
					} else {
						utils.Debugf("Check conflict. iosRow.Hash:%x, clientRow.Hash:%x\n", ioRow.Hash, clientRow.GetIndexBinRow().Hash)
						if bytes.Equal(ioRow.Hash, clientRow.GetIndexBinRow().Hash) {
							utils.Debugf("Conflict. NameKey:%s, sRow.Index:%d, Index:%d\n", clientRow.GetRowFileNameKey(), sRow.GetRowIndex(), index)
							utils.Debugf("sRow.Index: %d, Index: %d\n", sRow.GetRowIndex(), index)
							if sRow.GetRowIndex() == index {
								//if not equal, still needs to update the client
								removeFromServerChanges(serverFolder, sRow.GetIndexBinRow().Hash)
							} else {
								utils.Debugf("*** set row to conflict_new_index, row: %s", sRow.GetRowFileNameKey())
								sRow.Conflict = utils.CONFLICT_NEW_INDEX
								sRow.PreviousIndex = index
							}
							delete(clientFolder.Rows, index)
							continue
						} else {
							utils.Debugf("Conflict detected. Name exists on server, row Index: %d, NameKey: %s", index, clientRow.GetRowFileNameKey())
							//conflict = true;
							clientRow.Conflict = utils.CONFLICT_SAME_INDEX
							newServerChangeRows = append(newServerChangeRows, clientRow)
							continue
						}
					}
				}

				if serverRow, ok := serverFolder.Rows[index]; ok { //potential conflict
					clientIBRow := clientRow.GetIndexBinRow()
					serverIBRow := serverRow.GetIndexBinRow()
					if serverRow.GetRowFileNameKey() == clientRow.GetRowFileNameKey() {
						if clientIBRow.ToHashString() != serverIBRow.ToHashString() {
							//conflict = true;
							clientRow.Conflict = utils.CONFLICT_SAME_INDEX
							newServerChangeRows = append(newServerChangeRows, clientRow)
						}
					} else { //different file names, but same Index number.
						if clientRow.OperationMode == utils.MODE_NEW_FILE || clientRow.OperationMode == utils.MODE_NEW_DIRECTORY {
							clientRow.Conflict = utils.CONFLICT_NEW_INDEX
							clientRow.PreviousIndex = (index)
							newServerChangeRows = append(newServerChangeRows, clientRow)
						} else if clientRow.OperationMode == utils.MODE_RENAMED_FILE {
							//?
						} else if clientRow.OperationMode == utils.MODE_MODIFIED_CONTENTS ||
							clientRow.OperationMode == utils.MODE_MODIFIED_PERMISSIONS {

						}
					}

				}
			}

			n := uint32(len(newServerChangeRows))
			utils.Debugf("newServerChangeRows.Size: %d\n", n)
			if n > 0 {
				n += 200000 // to avoid Hash key conflicts
				for {
					if _, ok := serverFolder.Rows[n]; ok {
						n++
					} else {
						break
					}
				}
				ints := make([]uint32, len(newServerChangeRows))
				i := 0
				for _, r := range newServerChangeRows {
					if r.Conflict != utils.CONFLICT_REINSTATE_DIRECTORY {
						n++
						serverFolder.Rows[n] = utils.DeepCopy(r)
						ints[i] = n
						utils.Debugf("Conflict1 Index:%d\n", n)
					} else {
						ints[i] = r.GetRowIndex()
						utils.Debugf("Conflict2 Index:%d\n", ints[i])
					}
					utils.Debugf("newServerChangeRow Index: %d, n: %d, ints.i: %d; FileNameKey:%s", r.GetRowIndex(), n, ints[i], r.GetRowFileNameKey())
					i++
				}
				conflicts[serverFolder.FolderHash] = ints
				utils.Debugf("### for serverFolder:%s, rows.Size:%d\n", serverFolder.FolderHash, len(serverFolder.Rows))
			}
		} //end of if (changesFromClient.contains(serverFolder->folderHash))

		utils.Debugf("Add folder to serverChanges: %s\n", serverKey)
		this.serverChanges[serverKey] = serverFolder
	} //end of foreach keys of changesOnServer

	this.clientChanges = changesFromClient
	this.conflicts = conflicts
	utils.Debugf("leave merge, conflicts.Size: %d, %v\n", len(conflicts), conflicts)
	return true
}

func (this ServerBinLog) Info() string {
	return this.BinFileName // + "; " + this.currentTimestamp;
}

func (this *ServerBinLog) collectChanges() map[string]*utils.ModifiedFolder {
	this.objects = make(map[string]string)
	for _, change := range this.clientChanges {
		folderHash := change.FolderHash
		repoHash := change.RepoHash
		utils.Debug("CollectChanges. FolderHash: ", folderHash, "; changedRows.Size: ", len(change.Rows))
		parentHash := change.ParentHash

		var sFolder *utils.ModifiedFolder
		sFolder = nil
		var ints []uint32
		if serverFolder, ok := this.serverChanges[folderHash]; ok {
			//utils.Debugf("Folderhash found in serverChanges. folderHash:%s, changes.Rows.Size: %d\n", folderHash, len(change.Rows))
			//printFolder("Local now " + folderHash, &serverFolder);
			sFolder = serverFolder
			ints = this.conflicts[serverFolder.FolderHash]
		}
		_, folderName := filepath.Split(change.RelativePath)
		if change.HasThumbnail {
			task := utils.NewWriteTask(folderHash, utils.TASK_UPDATE_ROW)
			attribs := make(map[string][]byte)
			attribs[utils.ATTR_THUMBNAIL] = []byte{1}
			task.Attribs = attribs
			task.Index = 0
			this.WriteTasks = append(this.WriteTasks, task)
		}
		utils.Debugf("To call writeForOneFolder, folderHash:%s, parentHash: %s, change.relPath:%s, folderName:%s", folderHash, parentHash, change.RelativePath, folderName)
		folder := this.writeForOneFolder(repoHash, parentHash, folderHash, folderName, change.Rows, sFolder, ints)
		if folder != nil && this.serverChanges != nil {
			this.serverChanges[folderHash] = folder
		}
	}

	return this.serverChanges
}

type UInt32Slice []uint32

func (p UInt32Slice) Len() int {
	return len(p)
}
func (p UInt32Slice) Less(i, j int) bool {
	return p[i] < p[j]
}
func (p UInt32Slice) Swap(i, j int) {
	p[i], p[j] = p[j], p[i]
}
func changeFileName(folderHash string, row *utils.ModifiedRow, newFileName string, suffix string) *utils.ModifiedRow{
	row.FileName = newFileName
	key := utils.CalculateFileNameKey(newFileName, false, folderHash, suffix)
	bs := utils.FromHex(key)
	for i := 0; i < utils.FILE_NAME_KEY_BYTE_COUNT; i++ {
		row.Row[i+4] = bs[i]
	}
	return row;
}

func setRowOffset(row []byte, offset uint32) {
	utils.PutUint32(row, utils.FILE_OFFSET_INDEX, offset) //setRowOffset using current log's row count
}

func (this *ServerBinLog) writeForOneFolder(repoHash, parentHash string, folderHash, folderName string, clientChangedRows map[uint32]*utils.ModifiedRow,
	serverFolder *utils.ModifiedFolder, conflicts []uint32) *utils.ModifiedFolder {
	var data []byte
	//printFolder("Enter writeForOneFolder: "+folderHash, serverFolder)
	utils.Debug("Conflicts:", conflicts, "; clientChangedRows.Size: ", len(clientChangedRows))
	subPath := utils.HashToPath(folderHash)

	root := utils.GetUserRootOnServer(this.User)
	if val, ok := this.folderRoot[folderHash]; ok {
		root = utils.GetUserRootOnServer(val)
	}

	basePath := root + "/tree/" + subPath
	isZero := true
	keys := make([]uint32, 0, len(clientChangedRows))

	for k := range clientChangedRows {
		keys = append(keys, k)
	}
	sort.Sort(UInt32Slice(keys))

	spath := utils.HashToPath(folderHash)
	binFileName := root + "/tree/" + spath + ".bin"
	binFileSize := utils.FileSize(binFileName)
	currentRowCount := uint32(binFileSize / utils.FILE_INFO_BYTE_COUNT)
	logWriter := utils.NewMetaBinIO(basePath, true)
	rowCount := logWriter.GetRowCount()
	for _, k := range keys {
		row := clientChangedRows[k]
		setRowOffset(row.Row, rowCount)
		//utils.PutUint32(row.Row, utils.FILE_OFFSET_INDEX, rowCount);//setRowOffset using current log's row count
		if row.Conflict == utils.CONFLICT_SAME_INDEX {
			continue
		} else if row.Conflict == utils.CONFLICT_NEW_INDEX {
			//conflictedNewRows [k] = *row;
			continue
		}
		currentRowCount += this.updateMetaOnServerSide(repoHash, parentHash, folderHash, folderName, basePath, row, &data, currentRowCount)
		if row.SendBackToClient && serverFolder != nil {
			utils.Debugf("serverFolder insert row. fileNameKey: %s, %v\n", row.GetRowFileNameKey(), row)
			serverFolder.Rows[row.GetRowIndex()] = row
		}
		isZero = false
	}

	if serverFolder != nil && len(conflicts) > 0 {
		for _, k := range conflicts {
			row := serverFolder.Rows[k]
			if row == nil {
				utils.Debugf("NULL row, k:%d\n", k)
				utils.Debugf("NULL row, rows.count:%d\n", len(serverFolder.Rows))
			}
			utils.Debug("conflict. k:", k, " ; row.Conflict=", row.Conflict, "; row.Index:", row.GetRowIndex())
			if row.Conflict == utils.CONFLICT_SAME_INDEX {
				row.Conflict = utils.CONFLICT_NEW_INDEX
				row.AddFileNamePrefix(utils.CONFLICT_NAME_PREFIX)
				//newName := row.FileName
				//utils.Debug("Change conflict file name:", row.FileName, "; hash:", row.GetIndexBinRow().ToHashString(), "; row index:", row.GetRowIndex())
				//row = changeFileName(serverFolder.FolderHash, row, newName, this.suffix)
			} else if row.Conflict == utils.CONFLICT_REINSTATE_DIRECTORY {
				fileMode := row.GetIndexBinRow().FileMode
				fileMode = (fileMode & utils.PERMISSION_MASK) | utils.TYPE_DIRECTORY
				utils.PutUint32(row.Row, utils.FILE_INFO_BYTE_HEADER_COUNT, fileMode)
				row.Row[utils.FILE_OPMODE_POS] = utils.MODE_UNKNOWN
				serverFolder.Rows[row.GetRowIndex()] = row
				//delete(serverFolder.Rows, row.GetRowIndex()) //delete it F serverFolder so that it will not update the client.
				utils.Debugf("In writeForOneFolder. utils.CONFLICT_REINSTATE_DIRECTORY, rowIndex:%d, row:%v\n", row.GetRowIndex(), row.Row)
			}

			row.OperationMode = utils.MODE_NEW_FILE
			currentRowCount += this.updateMetaOnServerSide(repoHash, parentHash, folderHash, folderName, basePath, row, &data, currentRowCount)
			isZero = false
		}
	}
	if isZero {
		return serverFolder
	}

	return serverFolder
}

func (this *ServerBinLog) updateMetaOnServerSide(repoHash, parentHash string, folderHash, folderName string,
	basePath string, row *utils.ModifiedRow, data *[]byte, currentRowCount uint32) uint32 {

	spath := utils.HashToPath(folderHash)
	repo := utils.GetUserRootOnServer(this.User)
	if val, ok := this.folderRoot[folderHash]; ok {
		repo = utils.GetUserRootOnServer(val)
	}
	repoTreePath := repo + "/tree"
	baseFileName := repoTreePath + "/" + spath
	binFileName := baseFileName + ".bin"
	logWriter := utils.NewMetaBinIO(baseFileName, true)
	rowCount := logWriter.GetRowCount()
	ret := updateFileMetaFromModifiedRow(repoHash, repoTreePath, parentHash, folderHash, folderName, row, currentRowCount, &this.WriteTasks, this.User, this.suffix)
	if row.OperationMode != utils.MODE_DELETED_FILE && row.OperationMode != utils.MODE_DELETED_DIRECTORY {
		//one out of touch client may sync with an item in a already deleted directory.
		firstRow := utils.GetRowAt(binFileName, 0)
		if firstRow != nil && utils.IsFileModeDeleted((*firstRow).FileMode) {
			fileMode := utils.UndeleteDirectory((*firstRow).FileMode)
			list := make(map[string][]*utils.ModifiedRow)
			//updateFileModeAt(BinFileName, 0, FileMode)
			client.UpdateBinFile(binFileName, 0, fileMode, repoHash, folderHash, list, &this.WriteTasks, rowCount)
			undelete(repoHash, repoTreePath, (*firstRow).ToHashString(), folderHash, list, &this.WriteTasks, rowCount)
			if len(list) > 0 {
				for fHash, rows := range list {
					sFolder := utils.NewModifiedFolder()
					if sf, ok := this.serverChanges[fHash]; ok {
						sFolder = sf
					} else {
						utils.Debugf("Create new folder for %s\n", fHash)
						sFolder.FolderHash = fHash
						sFolder.Rows = make(map[uint32]*utils.ModifiedRow)
						//this.serverChanges [fHash] = *sFolder;
					}
					for _, mrow := range rows {
						index := mrow.GetRowIndex()
						sFolder.Rows[index] = utils.DeepCopy(mrow)
						//utils.Debugf("#FolderHash:%s, Index:%d, row: %v\n", fHash, Index, mrow.Row)
					}

					//printFolder("In updateMetaOnServerSide " + fHash, sFolder);
					this.serverChanges[fHash] = sFolder
				}

				//printChanges("In updateMetaOnServerSide " + folderHash, serverChanges)
			}
		}
	}

	return ret
}

func updateFileMetaFromModifiedRow(repoHash, repoTreePath string, parentHash string, folderHash, folderName string,
	row *utils.ModifiedRow, currentRowCount uint32, taskList *[]*utils.WriteTask, user string, suffix string) uint32 {
	spath := utils.HashToPath(folderHash)
	baseFileName := repoTreePath + "/" + spath
	//binFileName := baseFileName + ".bin"
	var newRowCount uint32 = 0
	index := row.GetRowIndex()
	fileHash := utils.GetHashFromRowBytes(row.Row)
	subPath := utils.HashToPath(fileHash)
	//utils.Debug("Enter updateFileMetaFromModifiedRow, repoHash:", repoHash, "; fileHash:", fileHash)
	binRow := row.GetIndexBinRow()
	hasNew := row.OperationMode == utils.MODE_NEW_FILE || row.OperationMode == utils.MODE_NEW_DIRECTORY || (row.OperationMode == utils.MODE_RENAMED_FILE && len(row.OldFolderHashAndIndex) > 0)
	if hasNew {
		newIndex := currentRowCount
		if newIndex == 0 {
			if taskList != nil {
				utils.Debug("Add CreateBinTask for folderHash:", folderHash, "; foldername:", folderName, "; filenamekey:", row.GetRowFileNameKey())
				t1, _ := client.CreateBinTask(repoHash, folderHash, parentHash, "", folderName)
				*taskList = append(*taskList, t1)
			}
			newIndex = 1
			newRowCount++
		} else if index > newIndex {
			index = newIndex
			row.SetRowIndex(newIndex)
			row.SendBackToClient = true
		}

		if row.Conflict == utils.CONFLICT_NEW_INDEX {
			utils.Debug("set SendBackToClient to true for row. index:", index, "; newIndex:", newIndex, "; fileHash:", fileHash)
			row.SetRowIndex(newIndex)
			row.SendBackToClient = true
		}
		if row.OperationMode != utils.MODE_RENAMED_FILE && len(row.GetRowFileNameKey()) > 0 {
			fKey := row.GetRowFileNameKey() // CalculateFileNameKey(row.FileName, utils.IsFileModeDirectory(binRow.FileMode), folderHash, suffix)
			if taskList != nil {
				*taskList = append(*taskList, client.CreateAddFileNameTask(folderHash, client.CreateRow(fKey, row.FileName)))
			}
		}

		rowIndex := row.GetRowIndex()
		//utils.Debugf("rowIndex: %d; newIndex: %d, fileNameKey:%s", rowIndex, newIndex, row.GetRowFileNameKey())
		if rowIndex < newIndex {
			//utils.Debugf("update row at %d, file: %s, row: %x", rowIndex, fileHash, row.Row)
			if taskList != nil {
				client.CreateUpdateRowTask(taskList, repoHash, folderHash, rowIndex, row.Row, row.Attribs, row.GetRowFileNameKey(), row.FileName, suffix, repoTreePath)
			}
		} else {
			//utils.Debugf("Append rowIndex:%d newIndex:%d; Hash: %s, with array: %x\n", rowIndex, newIndex, fileHash, row.Row)
			if taskList != nil {
				client.CreateAppendBinRowTask(taskList, repoHash, folderHash, rowIndex, row.Row, row.Attribs, row.GetRowFileNameKey(), row.FileName, repoTreePath)
			}
			newRowCount++
		}

		if row.SendBackToClient {
			utils.Debug("SendBackToClient is true, rowIndex:", rowIndex)
			*taskList = append(*taskList, client.CreateUpdateLocalCopyTask(folderHash, fileHash, rowIndex, binRow.FileMode, binRow.FileSize == 0))
		}
	} else if row.OperationMode == utils.MODE_MODIFIED_CONTENTS || row.OperationMode == utils.MODE_MODIFIED_PERMISSIONS ||
		row.OperationMode == utils.MODE_DELETED_FILE || row.OperationMode == utils.MODE_DELETED_DIRECTORY || row.OperationMode == utils.MODE_MOVED_FILE {
		if taskList != nil {
			client.CreateUpdateRowTask(taskList, repoHash, folderHash, index, row.Row, row.Attribs, row.GetRowFileNameKey(), row.FileName, suffix, repoTreePath)
		}

		if row.OperationMode != utils.MODE_DELETED_FILE && row.OperationMode != utils.MODE_DELETED_DIRECTORY {
			if taskList != nil {
				*taskList = append(*taskList, client.CreateUpdateLocalCopyTask(folderHash, fileHash, row.GetRowIndex(), binRow.FileMode, binRow.FileSize == 0))
			}
		} else {
			utils.Debugf("To delete local copy. opMode:%d, baseFile: %s, subPath:%s, fileNameKey:%s", row.OperationMode, baseFileName, subPath, row.GetRowFileNameKey())
			if taskList != nil {
				*taskList = append(*taskList, client.CreateDeleteFileTask(folderHash, fileHash, row.GetRowIndex()))
			}
		}
	} else if row.OperationMode == utils.MODE_REINSTATE_FILE || row.OperationMode == utils.MODE_REINSTATE_DIRECTORY {
		if taskList != nil && row.SendBackToClient {
			client.CreateUpdateRowTask(taskList, repoHash, folderHash, index, row.Row, row.Attribs, row.GetRowFileNameKey(), row.FileName, suffix, repoTreePath)
		}
	}

	if row.OperationMode == utils.MODE_RENAMED_FILE {
		movedFromAnotherDirectory := (len(row.OldFolderHashAndIndex) > 0)
		fKey := row.GetRowFileNameKey() // CalculateFileNameKey(row.FileName, utils.IsFileModeDirectory(binRow.FileMode), folderHash, suffix)
		_, foundKey := utils.ServerDbGetStringValue(user, fKey)
		if !foundKey {
			if taskList != nil {
				*taskList = append(*taskList, client.CreateAddFileNameTask(folderHash, client.CreateRow(fKey, row.FileName)))
			}
		}
		if !movedFromAnotherDirectory { //if the movedFromAnotherDirectory is true, appendLog already called above.
			if taskList != nil {
				client.CreateUpdateRowTask(taskList, repoHash, folderHash, index, row.Row, row.Attribs, row.GetRowFileNameKey(), row.FileName, suffix, repoTreePath)
			}
		}
	}

	if row.OperationMode == utils.MODE_RENAMED_DIRECTORY {
		fKey := row.GetRowFileNameKey() // CalculateFileNameKey(row.FileName, utils.IsFileModeDirectory(binRow.FileMode), folderHash, suffix)
		_, foundKey := utils.ServerDbGetStringValue(user, fKey)
		if !foundKey {
			if taskList != nil {
				*taskList = append(*taskList, client.CreateAddFileNameTask(folderHash, client.CreateRow(fKey, row.FileName)))
			}
		}

		utils.Debug("renamed directory, old row hash:", row.OldFolderHashAndIndex, "; newhash:", fileHash)
		if taskList != nil {
			fileNameKey := row.GetRowFileNameKey()
			client.CreateUpdateRowTask(taskList, repoHash, folderHash, index, row.Row, row.Attribs, fileNameKey, row.FileName, suffix, repoTreePath)
			*taskList = append(*taskList, client.CreateCopyBinTask(fileHash, row.OldFolderHashAndIndex, fileNameKey))
		}
	}

	if row.OperationMode == utils.MODE_DELETED_DIRECTORY {
		hash := utils.GetHashFromRowBytes(row.Row)
		var subs []string
		processed := make(map[string]bool)
		client.RecursivelyGetSubsAndSetFolderDeleted(repoTreePath, hash, &subs, processed, taskList)
	}
	//utils.Debugf("Return folderHash:%s, currentRowCount:%d, newCount:%d\n", folderHash, currentRowCount, newRowCount)
	return newRowCount
}



//Just before writing to various of .log files, get the size of them
func GetLogSizes(taskList []*utils.WriteTask, user string) map[string]int64 {
	folders := make(map[string]bool)

	for _, task := range taskList {
		if task.Mode != utils.TASK_UPDATE_LOCAL && len(task.FolderHash) > 0 {
			if !utils.SetContains(folders, task.FolderHash) {
				folders[task.FolderHash] = true
			}
		}
	}
	return GetLogSizesForFolders(folders, user)
}
func GetLogSizesForFolders(folders map[string]bool, user string) map[string]int64 {
	ret := make(map[string]int64)
	repo := utils.GetUserRootOnServer(user)
	for folderHash := range folders {
		subPath := utils.HashToPath(folderHash)
		r := repo
		//if(shareState == utils.REPO_SHARE_STATE_SHARE) {
		//	shareFolder := utils.GetShareFolderByRepoHashOnServer(user, repo + "tree/", folderHash )
		//	if(shareFolder != nil ){
		//		r = utils.GetUserRootOnServer(shareFolder.Owner);
		//	}
		//}
		pathLog := r + "tree/" + subPath + ".log"
		if utils.FileExists(pathLog) {
			logFileSize := utils.FileSize(pathLog)
			ret[folderHash] = logFileSize
		}
	}
	return ret
}

func ResponseDelivered(binLog *ServerBinLog, objects map[string][]byte, originator string) {
	//update data/clients file
	//save tasks to file first
	utils.Debug("Enter ResponseDelivered, time is ", time.Now(), "; user is ", binLog.User)
	defer utils.TimeTrack(time.Now(), "ResponseDelivered")
	taskFolder := utils.GetUserTaskRootOnServer(binLog.User)
	utils.MkdirAll(taskFolder)

	utils.SaveTasksCommit(taskFolder, binLog.WriteTasks)
	utils.Debug("ResponseDelivered. objects.len: ", len(objects))
	objectsTaskFile := taskFolder + utils.UPDATE_DAT
	if len(objects) > 0 {
		client.SaveUpdateDatTaskCommit(objectsTaskFile, objects, nil, binLog.shareState)
		client.DoSaveObjectsToFile(objects,utils.GetUserRootOnServer(binLog.User), false, true, binLog.User);
		utils.RemoveFile(objectsTaskFile)
	}

	//now do the job
	doTasks(binLog.User, taskFolder, binLog.DeviceID, binLog.WriteTasks,  binLog.end, binLog.shareState, binLog.FolderUpdates, originator)
}

func doTasks(user, taskFolder, deviceID string, tasks []*utils.WriteTask,  end int, shareState int32, folderUpdates map[string]*utils.ServerFolderUpdates, shareOriginator string) {
	utils.Debugf("Enter doTasks. user:%s, device:%s, end: %d, shareState: %d, deviceID: %s, shareOriginator: %s", user, deviceID, end, shareState, deviceID, shareOriginator)
	//ExecuteTasks(tasks, false, repo, user);
	filesizes := GetLogSizes(tasks, user)
	client.BatchExecuteTasks(user, tasks)

	utils.RemoveFile(taskFolder + "/END")
	folders := UpdateServerBinTasks(tasks, user, filesizes, shareState)
	utils.Debug("after saving bin file, folders:", folders)

	


	utils.Debug("To call SaveClientsDataFile here.")
	if shareOriginator != "" && shareOriginator != user {
		deviceID = "-1"
	}
	SaveClientsDatFile(user, deviceID, end, "", 0, false)

	//utils.RemoveFiles(files)
	utils.Debug("To call remove empty folders")
	utils.RemoveEmptyFolders(taskFolder, 4) //   tasks/0/0/1/1491312389_1/task_00000001
}

//Finish any incomplete client side tasks.
func HandleIncompleteServerTasks() {
	taskFolder := filepath.Clean(utils.GetTaskRootOnServer())
	if !utils.FileExists(taskFolder) {
		utils.MkdirAll(taskFolder)
	}
	folderLen := len(taskFolder)

	visit := func(path string, f os.FileInfo, err error) error {
		if f == nil || !f.IsDir() || path == taskFolder {
			return nil
		}
		//utils.Debugf("Visited: %s, pos:%d\n", path, folderLen)
		subPath := path[folderLen+1:]
		//utils.Debugf("Now path:%s\n", subPath)
		segments := strings.Split(subPath, string(filepath.Separator))
		n := len(segments)
		if n != 3 {
			return nil
		}
		user := fmt.Sprintf("%s%s%s", segments[0], segments[1], segments[2])
		//utils.Debugf("user is <%s>\n", user)
		if user == "001" {
			user = "1"
		} //for testing purpose
		handleUserTasks(user, path)

		return nil
	}

	filepath.Walk(taskFolder, visit)
}

func handleUserTasks(user, path string) {
	fis, err := utils.GetSubFolders(path)
	if err != nil {
		return
	}
	for _, fileInfo := range fis {
		name := fileInfo.Name()
		pos := strings.Index(name, "_")
		device := name[pos+1:]
		handleUserDeviceTasks(user, path+"/"+fileInfo.Name(), device)
	}
}

func handleUserDeviceTasks(user, path, deviceID string) {
	updateDatFile := path + "/" + utils.UPDATE_DAT
	var shareState int32
	if utils.FileExists(updateDatFile) {
		bs, err := utils.Read(updateDatFile)
		if err != nil {
			utils.RemoveFile(updateDatFile)
		} else {
			tasksObj := utils.UpdateDatTask{}
			if proto.Unmarshal(bs, &tasksObj) == nil {
				shareState = tasksObj.ShareState
				client.DoSaveObjectsToFile(tasksObj.Objects, utils.GetUserRootOnServer(user), false, true, user)
			}
			utils.RemoveFile(updateDatFile)
		}
	}
	if utils.FileExists(updateDatFile) {
		return
	} //updateDatFile still exists, error occurred and returns.

	fis, err := utils.GetSubFolders(path)
	if err != nil {
		return
	}
	var tasks []*utils.WriteTask

	if !utils.FileExists(path+"/END") && len(fis) > 0 { //incomplete saving of task files
		//utils.Debugf("ServerSide. task.END file does not exist. dir: %s", path)
		utils.RemoveAllSubItems(utils.GetTasksFolder())
		return
	}

	for _, fileInfo := range fis {
		tasksObj := new(utils.WriteTask)
		fileName := path + "/" + fileInfo.Name()
		//utils.Debugf("To process saved server task: %s\n", fileName)
		bs, err := utils.Read(fileName)
		if err != nil {
			utils.Debugf("Error: %v\n", err)
			continue
		}
		if proto.Unmarshal(bs, tasksObj) == nil {
			tasks = append(tasks, tasksObj)
		}
	}
	doTasks(user, path, deviceID, tasks, 0, shareState, nil, "")
}

func appendToArray(repoTree string, prevSize int, hash string, logFileSize int) []byte {
	var data []byte = nil
	subPath := utils.HashToPath(hash)
	pathLog := repoTree + "/" + subPath + ".log"
	val := make([]byte, 12)
	utils.PutInt(val, 0, prevSize)
	utils.PutUint32(val, 4, uint32(time.Now().Unix()))

	if logFileSize < 0 {
		logFileSize = int(utils.FileSize(pathLog))
	}
	utils.PutUint32(val, 8, uint32(logFileSize))

	data = append(data, val...)
	data = append(data, utils.FromHex(hash)...)
	//utils.Debugf("ApppendToArray,Hash:%s, data:%x\n", Hash, *data)
	return data
}

func (this *ServerBinLog) loadRowsFromLogFile(folder *utils.ModifiedFolder, owner string, updates *utils.ServerFolderUpdates, rowCount *int) (*utils.ServerFolderUpdates, bool) {
	if updates == nil {
		utils.Debug("nil ServerFolderUpdates")
		return nil, false
	}
	utils.Debug("Enter loadRowsFromLogFile, owner:", owner, "; this.user:", this.User, "; updates:", (updates))
	root := utils.GetUserRootOnServer(owner)
	base := root + "/tree/" + utils.HashToPath(folder.FolderHash)
	fileName := base + ".log"

	utils.Debugf("Enter loadRowsFromLogFile F %s, begin:%d, end:%d; folder.Hash:%s\n", folder.FolderHash, folder.Offset, folder.End, folder.FolderHash)
	file, err := os.Open(fileName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "loadRowsFromLogFile. File:%s. Cannot open file: %s\n", fileName, err)
		return nil, false
	}
	defer file.Close()
	if folder.Offset > 0 {
		file.Seek(int64(folder.Offset), 0)
	}
	begin := int(folder.Offset)
	end := int(folder.End)
	//folderInfo := fileName[0 : len(fileName)-4]
	utils.Debugf("FolderInfo:%s, begin: %d, end: %d\n", folder.FolderHash, begin, end)
	var index uint32 = 0
	readCount := 0
	count := 0
	for {
		buf := make([]byte, utils.FILE_INFO_BYTE_COUNT*512)
		readCount, err = file.Read(buf)
		utils.Debugf("In loadRows, readCount:%d", readCount)
		if err != nil || readCount == 0 {
			break
		}
		start := 0
		if folder.Rows == nil {
			folder.Rows = make(map[uint32]*utils.ModifiedRow)
		}
		utils.Debug("start: ", start, "; readCount: ", readCount)
		for start < readCount && (begin+count+utils.FILE_INFO_BYTE_COUNT) <= end {

			var s = buf[start : start+utils.FILE_INFO_BYTE_COUNT]
			var row = utils.NewModifiedRow(false)

			//var bs []byte
			//bs = make([]byte, utils.FILE_INFO_BYTE_COUNT)
			//copy(bs, s) //MUST make a copy, otherwise it will cause serious bug.
			row.Row = s

			start += utils.FILE_INFO_BYTE_COUNT
			count += utils.FILE_INFO_BYTE_COUNT

			irow := row.GetIndexBinRow()
			//if(this.shareState == utils.REPO_SHARE_STATE_SHARE && utils.IsFileModeDirectory(io.FileMode) ){
			//	continue;
			//}
			fileNameKey := irow.FileNameKey // row.GetRowFileNameKey()
			ioUser := fmt.Sprintf("%d", irow.User)
			fName, foundKey := utils.ServerDbGetStringValue(ioUser, fileNameKey) // items.get(FileNameKey);
			if !foundKey {
				fName, foundKey = utils.ServerDbGetStringValue(owner, fileNameKey)
			}
			if foundKey {
				row.FileName = fName
			}
			index = irow.Index //row.GetRowIndex()
			utils.Debugf("In loadRowsFromLogFile, Index:%d, NameKey:%s, opMode:%d", index, row.GetRowFileNameKey(), row.GetOpMode())
			folder.Rows[index] = row // append(folder.Rows, row);
			key := utils.CreateXattribKey(folder.FolderHash, uint32(index))
			utils.Debug("ioUser:", ioUser, "; user:", owner, "; key:", key)
			xa, found := utils.ServerDbGetStringValue(ioUser, key) // items.get(FileNameKey);
			if !found {
				xa, found = utils.ServerDbGetStringValue(owner, key)
			} else {
				utils.Debug("xa not found  for user:", ioUser)
			}
			if found {
				utils.Debug("Found xattrib for row: ", fName)
				fattr := utils.FileAttribs{}
				fattr.Attribs = make(map[string][]byte)
				if proto.Unmarshal([]byte(xa), &fattr) == nil {
					utils.Debug("Set row.Attribs value.size: ", len(fattr.Attribs), "; hash:", fattr.Attribs["hash"])
					row.Attribs = fattr.Attribs
				} else {
					utils.Debug("Couldn't unmarshal attribs for fName:", fName)
				}
			} else {
				utils.Debug("xa not found at all--------------")
			}
			if updates == nil {
				utils.Debug("Error, nil updates")
			}
			updates.Logs = append(updates.Logs, utils.DeepCopy(row))
			(*rowCount) ++;
			if *rowCount >= utils.MAX_CHANGE_COUNT_SERVER {
				utils.Debug("rowCount:", *rowCount)
				return updates, false;
			}
		}
	}
	utils.Debug("Leaving loadRowsFromLogFile,  logs.count: ", len(updates.Logs), " for folderHash: ", folder.FolderHash)
	this.FolderUpdates[folder.FolderHash] = updates
	return updates, true
}



func HandleVerfication(w http.ResponseWriter, r *http.Request) {
	u, _ := url.Parse(r.RequestURI)
	email := strings.ToLower(u.Query().Get("email"))
	code := u.Query().Get("code")
	v := CreateHash(email)
	//utils.Info("email:", email, "; v:", v)
	if v == code {
		dir := utils.GetRootOnServer() + "register";
		fileName := dir + "/" + v
		utils.WriteString(fileName, "ok")
		//utils.Info("Write file:", fileName)
		w.Write([]byte("true"))
	}else{
		w.Write([]byte("false"))
	}

}

func CreateHash(text string)string{
	k := GetMainServerAuthKey()
	h := utils.NewHmac(k[:])
	h.Write([]byte(text))
	hash2 := fmt.Sprintf("%x", h.Sum(nil))
	return hash2;
}




func checkHash(text, hash1 string) bool {
	hash2 := CreateHash(text);

	if hash1 != hash2 {
		utils.Debug("hash1:", hash1, "; hash2:", hash2)
		return false
	} else {
		utils.Debug("hashes matched")
		return true
	}
}

func PutHandler(w http.ResponseWriter, r *http.Request) {
	//utils.Debugf("Put.uri:%s, P:%s. token:%s, header:%v", r.RequestURI, r.URL.P, r.Header["Token"], r.Header)
	accessToken := r.Header.Get("Token")
	command := utils.GetLastUrlPathComponent(r.URL.Path)
	utils.Debug("PutHandler, command is ", command)


	user := r.Header.Get("UserID")
	utils.Debug("Enter PutHandler. Token:", accessToken, "; user: ", user, "; request: ", r.RequestURI)
	if accessToken == "" || user == "" {
		utils.Debug("Null user or token")
		http.Error(w, "Error", utils.HTTP_BAD_REQUEST)
		return
	}

	var userID int
	var err error
	if userID, err = strconv.Atoi(user); err != nil {
		utils.Debug("UserID is not right")
		http.Error(w, "Error", utils.HTTP_BAD_REQUEST)
		return
	}
	userObj, errCode := GetUserAccountByID(userID)
	if errCode != 0 {
		utils.Debug("DB not working")
		http.Error(w, "Error", utils.HTTP_INTERNAL_ERROR)
		return
	}
	if userObj == nil {
		utils.Debug("UserID object is nil")
		http.Error(w, "Error", utils.HTTP_UNAUTHORIZED)
		return
	}

	utils.Debug("PUT command: ", command)
	if command == "replace" {
		ReplaceContents(w, r, user)
	} else if command == "upload" {
		HandleFileUpload(w, r)
	}
}

func ReplaceContents(w http.ResponseWriter, r *http.Request, user string) {
	tmpDir := utils.GetTmpOnServer()
	filename := tmpDir + utils.GenerateRandomHash()
	f, err := os.OpenFile(filename, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0644)
	//f, err := utils.Create(filename, 0644)
	if err != nil {
		utils.Debug("ReplaceContents. Couldn't create file: ", filename)
		return
	}
	defer func() {
		if f != nil {
			f.Close()
		}
		utils.RemoveFile(filename)
	}()
	var size int64
	if size, err = io.Copy(f, r.Body); err != nil {
		utils.Debug("Failed to copy file: ", filename)
		http.Error(w, "Error", utils.HTTP_INTERNAL_ERROR)
		return
	}
	f.Close()
	f = nil
	utils.Debugf("Saved tlz size:%d to %s", size, filename)
	userRoot := utils.GetUserRootOnServer(user)
	utils.RemoveAllFiles(userRoot + "/names")
	utils.RemoveAllFiles(userRoot + "/objects")
	utils.RemoveAllFiles(userRoot + "/tree")

	if err = utils.UnzipTo(filename, userRoot); err != nil {
		utils.Debug("Couldn't unzip to ", userRoot, "; error is ", err)
		http.Error(w, "Error", utils.HTTP_INTERNAL_ERROR)
		return
	}

	utils.RemoveFile(userRoot + "/data/clients.dat")
	utils.RemoveFile(userRoot + "/data/server.bin")
	utils.Debug("PutHandler completed. userRoot: ", userRoot)
}

func getDataRootOnServer() string {
	//config := utils.LoadServerConfig() //  properties.LoadFile(APP_CONFIG_FILE, properties.UTF8)
	//return config.DataPath             //GetString("server", "")
	return "/tmp/data/blob/"
}
func removeFromServerChanges(serverFolder *utils.ModifiedFolder, hash []byte) {
	for index, row := range serverFolder.Rows {
		if bytes.Equal(row.GetIndexBinRow().Hash, hash) {
			//delete element i F slice:  a = append(a[:i], a[i+1:]...)
			delete(serverFolder.Rows, index)
			//serverFolder.Rows = append(serverFolder.Rows[:Index], serverFolder.Rows[Index+1:]...)
			return
		}
	}
}

func HandleFileUpload(w http.ResponseWriter, r *http.Request) {
	u, _ := url.Parse(r.RequestURI)
	fileHash := u.Query().Get("h")
	utils.Debug("PUT.hash: ", fileHash)
	if fileHash == "" {
		return
	}
	dataRoot := getDataRootOnServer()
	filename := dataRoot + utils.HashToPath(fileHash) + utils.EXT_OBJ
	dir := filepath.Dir(filename)
	if !utils.FileExists(dir) {
		utils.MkdirAll(dir)
	}

	utils.Debug("FileName: ", filename)
	f, err := os.OpenFile(filename, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0644)
	if err != nil {
		utils.Debug("HandleFileUpload. Couldn't create file: ", filename)
		return
	}
	defer func() {
		if f != nil {
			f.Close()
		}
	}()
	if _, err = io.Copy(f, r.Body); err != nil {
		utils.Debug("Failed to copy file: ", filename)
		http.Error(w, "Error", utils.HTTP_INTERNAL_ERROR)
		return
	}
	utils.Debug("HandleFileUpload finished.")
}




func ServeFile(w http.ResponseWriter, r *http.Request) {
	dataRoot := getDataRootOnServer()
	fileHash := utils.GetLastUrlPathComponent(r.URL.Path)
	filename := dataRoot + utils.HashToPath(fileHash) + utils.EXT_OBJ
	utils.Debug("ServeFile, filename: ", filename)
	http.ServeFile(w, r, filename)
}

func createInitialShareZip(userID, hash string, in *utils.UserRequest) string {
	bs, err := proto.Marshal(in)
	if err != nil {
		return ""
	}
	folder := filepath.Clean(utils.GetTmpOnServer() + utils.GenerateRandomHash() + "/init/")
	defer utils.RemoveAllFiles(folder)
	utils.MkdirAll(folder)
	utils.WriteBytesSafe(folder+"/request", bs)
	//zip1 := filepath.Clean(folder + ".o.tar.lz4");
	//utils.CreateZip([]string{folder}, nil, nil, zip1)

	repo := utils.GetUserRootOnServer(userID)
	folderBinFile := repo + "/tree/" + utils.HashToPath(hash) + utils.EXT_BIN
	utils.CopyFile(folderBinFile, folder+"/bin")
	//utils.CopyDatFiles(folderBinFile, repo + "/objects/", folder + "/objects/")
	zip2 := filepath.Clean(folder + ".s.tar.lz4")
	utils.CreateZip([]string{folder}, nil, nil, zip2)
	utils.Debug("createInitialShareZip, folder: ", folder, "; zip: ", zip2)
	return zip2
}




//func HandleGetUserInfo(in *utils.UserRequest, response * utils.ActionResponse) {
//	owner := string(in.Data["user"]);
//	utils.Debug("in.UserID:", in.UserID, "; owner:", owner)
//
//	u, _ := GetUserAccountBy(owner, true);
//	response.Data["server"] = []byte(u.Server)
//	response.Data["name"] = []byte(u.Name)
//	response.Data["prefix"] = []byte(GetOfficialServerUserPrefix(owner));//the prefix is the part after bucket.
//}

func InvokeServerAction(server string, userID string, deviceID uint32, action string, tasks []*utils.WriteTask, data map[string][]byte, data2 map[string][]byte, data3 map[string][]byte) (*utils.ActionResponse, error) {
	if data == nil {
		data = make(map[string][]byte)
	}
	request := utils.UserRequest{
		UserID:   userID,
		Action:   action,
		DeviceID: deviceID,
		Data:     data,
		Version:  utils.VERSION,
	}
	request.Tasks = tasks
	request.Data2 = data2
	request.Data3 = data3
	if c, conn, err := utils.NewGrpcClientWithServer(server, utils.SERVER_MAIN_PORT, true, nil); err == nil {
		defer conn.Close()
		if response, err := c.SendData(context.Background(), &request); err != nil {
			utils.Warn("Error occurred in InvokeServerAction.SendData ", err)
			return nil, err
		} else {
			utils.Debug("CallServer  server:", server, "; action: ", action)
			return response, nil
		}
	}
	utils.Debug("InvokeServerAction returned error")
	return nil, errors.New("no connection")
}

func (this *ServerBinLog) readLogSinceOnOwner(repoTree string, fileOffset uint32, shareFolder *utils.ShareFolder) {
	u, err := GetUserAccountBy(shareFolder.Owner, true)
	if err != 0 {
		return
	}
	data := make(map[string][]byte)
	data["offset"] = []byte(fmt.Sprintf("%d", fileOffset))
	utils.Debug("user:", u.Name, "; id:", u.ID, "; u.server:", u.Server, "fileOffset:", fileOffset)
	if resp, err := InvokeServerAction(u.Server, shareFolder.Owner, uint32(utils.ToInt(this.DeviceID)), "readLogSince", nil, data, nil, nil); err == nil {
		bs := resp.Data["binlog"]
		binLog := utils.BinLogResponse{}
		if proto.Unmarshal(bs, &binLog) == nil {
			this.serverChanges = binLog.ServerChanges
			if binLog.FolderUpdates != nil {
				this.FolderUpdates = binLog.FolderUpdates
			} else {
				this.FolderUpdates = make(map[string]*utils.ServerFolderUpdates)
			}
			utils.Debug("readLogSinceOnOwner returns. changes.len:", len(this.serverChanges), "; updates.len:", len(this.FolderUpdates))
			//func (this *ServerBinLog) readLogSince(repoTree string, fileOffset uint32, fileEnd int, shareFolder * utils.ShareFolder, user string) bool {
			//this.readLogSince(repoTree, fileOffset, 0, shareFolder);
		}
		return
	}
}

func marshalObj(pb proto.Message) []byte {
	bs, err := proto.Marshal(pb)
	if err != nil {
		return nil
	}
	return bs
}
func (this *ServerBinLog) loadRowsFromLogFileOnOwner(folder *utils.ModifiedFolder, owner string, updates *utils.ServerFolderUpdates) (*utils.ServerFolderUpdates, bool) {
	utils.Debug("Enter loadRowsFromLogFileOnOwner, owner:", owner, "; this.user:", this.User, "; folder:", folder.FolderHash)
	u, err := GetUserAccountBy(owner, true)
	if err != 0 {
		utils.Debug("loadRowsFromLogFileOnOwner return 1")
		return nil, false
	}
	data := make(map[string][]byte)
	data["owner"] = []byte(owner)
	data["folder"] = marshalObj(folder)
	utils.Debug("To call loadRowsFromLogFile")
	if resp, err := InvokeServerAction(u.Server, this.User, uint32(utils.ToInt(this.DeviceID)), "loadRowsFromLogFile", nil, data, nil, nil); err == nil {
		bs := resp.Data["binlog"]
		binLog := utils.BinLogResponse{}
		if proto.Unmarshal(bs, &binLog) == nil {
			this.FolderUpdates = binLog.FolderUpdates
			updates := this.FolderUpdates[folder.FolderHash]
			return updates, true
		}
	}

	return nil, false
}

func GetOfficialServerUserPrefix(userID string)string{
	

	key := GetMainServerAuthKey();
	h := utils.NewHmacSha224(key[:]);
	h.Write([]byte(userID)); //h.Write([]byte(utils.IntStringToPath(userID)))
	userPrefix := fmt.Sprintf("%x", h.Sum(nil));
	return userPrefix;
}

func DoSaveObjectsToFileOnServer(objects map[string][]byte,user, root string, saveSharedToo bool) {
	client.DoSaveObjectsToFile(objects, root, saveSharedToo, true, user)
}

func NewServerFolderUpdates(repoHash, folderHash string) *utils.ServerFolderUpdates {
	mfolder := new(utils.ServerFolderUpdates)
	mfolder.FolderHash = folderHash
	mfolder.RepoHash = repoHash
	return mfolder
}

func isFolderContainedOrParent(changesFromClient []*utils.ModifiedFolder, folderHash string) bool {
	utils.Debug("Enter isFolderContainedOrParent 111, size: ", len(changesFromClient), ", folderHash: ", folderHash)

	for _, folder := range changesFromClient {
		if folderHash == folder.FolderHash {
			return true
		}
		relativePath := filepath.Dir(folder.RelativePath)
		for {
			if relativePath == utils.ROOT_NODE {
				break
			}
			hash := utils.GetFolderPathHash(relativePath)
			utils.Debug("relativePath:", relativePath, "; hash: ", hash, "; folderHash: ", folderHash, "; folder.FolderHash:", folder.FolderHash)
			if hash == folderHash {
				return true
			}
			relativePath = filepath.Dir(relativePath)
		}
	}
	utils.Debug("Leaving isFolderContainedOrParent 111")
	return false
}

func containsFolder(folders []*utils.ModifiedFolder, folderHash string) *utils.ModifiedFolder {
	for _, folder := range folders {
		if folder.FolderHash == folderHash {
			return folder
		}
	}
	return nil
}

func undelete(repoHash, repoTreePath string, folderHash string, itemHash string, list map[string][]*utils.ModifiedRow, tasks *[]*utils.WriteTask, rowCount uint32) {
	subPath := utils.HashToPath(folderHash)
	baseFileName := repoTreePath + "/" + subPath
	binFileName := baseFileName + ".bin"
	row := client.GetRowByHash(binFileName, itemHash)
	if row == nil {
		return
	}
	index := row.Index
	if index > 0 && utils.IsFileModeDeleted(row.FileMode) {
		fileMode := utils.UndeleteDirectory(row.FileMode)
		client.UpdateBinFile(binFileName, index, fileMode, repoHash, folderHash, list, tasks, rowCount)
		//updateFileModeAt(BinFileName, int((*row).Index), (FileMode))
	}
	firstRow := utils.GetRowAt(binFileName, 0)
	if firstRow != nil && utils.IsFileModeDeleted(firstRow.FileMode) {
		fileMode := utils.UndeleteDirectory(firstRow.FileMode)
		//updateFileModeAt(BinFileName, 0, (FileMode))
		client.UpdateBinFile(binFileName, 0, fileMode, repoHash, folderHash, list, tasks, rowCount)
		pHash := (*firstRow).ToHashString()
		undelete(repoHash, repoTreePath, pHash, folderHash, list, tasks, rowCount)
	}
}
