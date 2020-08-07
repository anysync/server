// Copyright (c) 2020, Yanbin (Henry) Zheng <ybzheng@gmail.com>
// All rights reserved.
//
// Use of this source code is governed by a AGPLv3 license that can be
// found in the LICENSE file.
package utils

import (
	"database/sql"
	"fmt"
	//"github.com/boltdb/bolt"
	"github.com/golang/protobuf/proto"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"path/filepath"
	"strings"
	"sync"
	"time"
	_ "github.com/mattn/go-sqlite3"
)

func Reconnect(toSleep bool, callResetGetAll bool, ackCallback func()) {
	Debug("Enter Reconnect. toSleep:", toSleep, "; callResetAll:", callResetGetAll)
	if toSleep {
		time.Sleep(time.Second * 60)
	}
	Listener(callResetGetAll,  "",ackCallback)
}

func GrpcReport(code int, msg string) {
	Debug("GrpcReport.Code is ", code, "; msg is ", msg)
	go Reconnect(true, false, nil)
}

var hasOneListener bool
var listenerMutex = &sync.Mutex{}
var listenerConnection *grpc.ClientConn;
var listenerClient SyncResult_SubscribeClient;

func CloseListener(){
	listenerMutex.Lock()
	defer listenerMutex.Unlock()

	if(listenerClient != nil){
		listenerClient.CloseSend();
		listenerClient = nil;
	}

	if(listenerConnection != nil) {
		listenerConnection.Close();
		listenerConnection = nil;
	}

	hasOneListener = false;
	//Reconnect(false, false, nil) //moved to GrpcReport()
}

//@getAllMode: empty - GetAll ; "serverbin" - only include server.bin file in the result zip.
func Listener(callResetGetAll bool, getAllMode string, ackCallback func()) {
	listenerMutex.Lock()
	defer listenerMutex.Unlock()
	if hasOneListener {
		return;
	}

	if !CurrentFileExists() {
		Debug("No subscribe because of no current file.")
		return
	}

	if response, err := SendData(ACTION_ACK, "", "" , nil); err == nil {
		Debug("Got ACK back.")
		handleAck(response.Data, ackCallback)
	}else{
		SendToLocal(MSG_PREFIX + "Error: " + err.Error())
		return;
	}

	r := GrpcReport
	c, conn, err := NewGrpcListenerClient(r)
	listenerConnection = conn;
	if err != nil {
		Warnf("Could not connect3: %v", err)
		return
	}

	hasOneListener = true;

	if CurrentAccessToken == nil || len(CurrentAccessToken) == 0 {
		GetAccessToken()
		if CurrentAccessToken == nil || len(CurrentAccessToken) == 0 {
			Debug("No subscribe because of no access token")
			return
		}
	}
	in := NewGrpcUserRequest()
	stream, err := c.Subscribe(context.Background(), in)
	listenerClient = stream;
	if err != nil {
		Warn("Error occurred during creating new Listener", err)
		return
	}
	if callResetGetAll {
		Debug("To Call CallResetGetAll...")
		CallResetGetAll(getAllMode)
	}
	go listenLoop(stream, in, ackCallback,  func() {
		CloseListener();
	})
}

func handleAck( Data map[string][]byte, ackCallback func()){
	if CurrentUser == nil {
		CurrentUser = new(UserAccount);
	}
	CurrentUser.ID = int32(ToInt(string(Data["user"])));
	CurrentUser.Quota = uint32(ToInt(string(Data["quota"])))
	CurrentUser.AccountType = int32(ToInt(string(Data["type"])))
	CurrentUser.Prefix = string(Data["prefix"])
	CurrentUser.Bucket = string(Data["bucket"])
	CurrentUser.Expiry =  ToUint32(string(Data["expiry"]))
	CurrentUser.Email = string(Data["email"])
	CurrentUser.OrderID = string(Data["order"])
	if(ackCallback != nil) {
		ackCallback();
	}
}

var ResetCallback func()
var AskRestore = true

func listenLoop(stream SyncResult_SubscribeClient, in *UserRequest, ackCallback func(),  closeFunc func()){
	defer closeFunc();
	for {
		res, err := stream.Recv()
		if err != nil {
			Info("Async connection error occurred:", err, "; Try reconnecting to server after a while.")
			return
		}
		Debugf("Received async msg:%v", res)
		if res.Action == ACTION_UPDATE {
			headers := make(map[string]string)
			if s, ok := res.Data["size"]; ok {
				Debug("##################### to send out getupdates, size: ", string(s))
				headers["size"] = string(s) //size is the size of server.bin
			}
			go GetUpdatesFromServer(headers)
		} else if res.Action == ACTION_DOWNLOAD {
			go resetGetAllDownloadFile(in.UserID, res.Data)
		} else if res.Action == ACTION_SHARE_FOLDER {
			go refreshShareFolder()
		}else if res.Action == ACTION_SHARE_ACTION {

		}else if res.Action == ACTION_ACCT_TYPE_CHANGE  || res.Action == ACTION_ACK {
			Debug("Account type changed to:", string(res.Data["type"]), "; Quota is ", string(res.Data["quota"]), "GB")
			handleAck(res.Data, ackCallback)
			if(res.Action == ACTION_ACCT_TYPE_CHANGE) {
				SendToLocal("MSG:Account type changed. Quota is " + string(res.Data["quota"]) + "GB")
			}
		} else if res.Action == ACTION_VERIFY {
			hash := string(res.Data["hash"])
			folder := string(res.Data["folder"])
			status := string(res.Data["status"])
			code := string(res.Data["code"])
			Debug("verify. folder:", folder, "hash:", hash, ";code:", code)
			path := GetFolderFullPath(folder)
			if code == "200" {
				SendToLocal("verified:" + path)
			} else {
				SendToLocalWithParams("nverified", "msg", status, "hash", hash, "folder", folder, "code", code)
			}
		}
	}
}

func GetUpdatesFromServer(headers map[string]string) {
	url := "http://127.0.0.1:65066/rest/rescan"
	HttpGetCommand(url, nil)
}

var isDownloadingAllMeta = false

//@getAllMode: empty - GetAll ; "serverbin" - only include server.bin file in the result zip.
func CallResetGetAll(mode string) {
	Debug("Enter CallReset...token: ", CurrentAccessToken)
	SendToLocal(MSG_PREFIX + "To request user data from server ...")
	if isDownloadingAllMeta {
		return
	}
	isDownloadingAllMeta = true
	c, conn, err := NewGrpcClient()
	if err != nil {
		Warnf("did not connect: %v", err)
		return
	}
	defer conn.Close()
	config := LoadConfig()
	data := make(map[string][]byte);
	data["mode"] = []byte(mode)
	request := UserRequest{
		UserID: config.User,
		Action: ACTION_RESET_GET_ALL,
		DeviceID: ToUint32(config.DeviceID),
		Data: data,
	}

	SetUserRequestNow(&request, config.User, config.DeviceID)
	Debug("To call resetgetall on the server")
	_, err = c.CallAction(context.Background(), &request)
	if err != nil {
		Warnf("could not finish ResetGetAll: %v", err)
	}
	Debug("Returned from resetgetall")
}

//Notified from main server, and download zip file from main server.
func resetGetAllDownloadFile(userID string, data map[string][]byte) { //file is like "39823bddc68781e16acba2689c9a37557a6ce6262fabc196d8086466.tlz"
	file :=string(data["file"])
	Debug("Download file, file is ", file)
	defer func() { isDownloadingAllMeta = false }()
	if file == "" {
		return
	}
	config := LoadConfig()
	tmpFile := GetTopTmpFolder() + file
	pos := strings.LastIndex(tmpFile, ".")
	tmpFile = tmpFile[0:pos] + ".tar.lz4";
	fileUrl := fmt.Sprintf("%s/tmp/%s", config.GetUrlPrefix(), file)
	Debug("FileUrl: ", fileUrl)
	headers := CreateHttpAuthHeader()
	if headers == nil {
		return
	}
	SendToLocal(MSG_PREFIX + "Downloading meta data files from server ...")
	if err:=HttpGetFile(fileUrl, tmpFile, headers); err!=nil {
		Warn("Cannot retrieve file from server.")
		return;
	}
	SendToLocal(MSG_PREFIX + "Download completed. To restore meta data locally ...")

	task := NewWriteTask("", TASK_RESET_ALL)
	task.FolderHash = tmpFile
	task.Data = string(data["offset"])
	task.Time = uint32(time.Now().Unix())
	SaveTaskCommit(task, GetResetAllTasksFolder())
	if err := ExecuteResetAll(task); err == nil {
		Info("All meta files have been downloaded and files are restored to configured locations.")
		RemoveFile(GetResetAllTasksFolder())
	}else {
		return;
	}

	Debug("To reset user with id:", userID)
	InitHashSuffix()
	//ResetUser(userID)

	folders := GetLocalFolders()
	dirs := strings.Join(folders, ",")
	if AskRestore {
		SendToLocal("askrestore:" + dirs)
	}
	if(ResetCallback != nil){
		ResetCallback();
	}
}

func refreshShareFolder(){
	GetUpdatesFromServer(nil)
}

func GetLocalFolders() []string {
	var folders []string;
	repos := GetRepositoryList();
	for _, r := range repos{
		folders = append(folders, r.Local)
	}

	return folders;
}
func ExecuteResetAll(task *WriteTask) error {
	Info("Execute reset_all task")
	ResetNamesDb();//so files can be replaced on windows
	RemoveAllFiles(GetTopTreeFolder())
	RemoveAllFiles(GetTopObjectsFolder())
	RemoveAllFiles(GetTopNamesFolder())
	RemoveFile(GetAppHome() + "/server.bin")
	//All the above must be removed first, otherwise UnzipTo does not work correctly, some of files cannot be unzipped.
	if !FileExists(GetTopTreeFolder()) {
		Debug("Tree dir does not exist")
	}
	Debug("To unzip file ", task.FolderHash, " to ", GetAppHome())
	//UnzipTo(task.FolderHash, "/tmp/l")
	UnzipTo(task.FolderHash, filepath.Clean(GetAppHome()))
	defer RemoveFile(task.FolderHash)

	return nil
}

func NewWriteTask(folderHash string, m uint32) *WriteTask {
	task := new(WriteTask)
	task.FolderHash = folderHash
	task.Mode = m
	return task
}

func SaveTaskCommit(task *WriteTask, fileName string) error {
	bytes, err := proto.Marshal(task)
	if err != nil {
		return err
	}
	err = WriteBytesSafe(fileName, bytes)
	return err
}

//func NewTaskDb(dbFile string)( *bolt.DB, error){
//	//taskFolder := GetTasksFolder();
//	//dbFile := taskFolder + "/data.db";
//
//	o := &opt.Options{
//		OpenFilesCacheCapacity: 8,
//		NoWriteMerge:true,
//	}
//	db, err := leveldb.OpenFile(dbFile,  o)
//	if err != nil {
//		Error(err)
//		return nil, err
//	}
//	return db,nil
//}
func NewDownloadDb()(*sql.DB){
	taskFolder := GetTasksFolder();
	dbFile := taskFolder + "/download.db";
	return NewDb(dbFile)
}

func SaveTasksCommit(taskFolder string, ts []*WriteTask)  {
	Debug("Enter SaveTasksCommit. len:", len(ts))
	defer Debug("Leave SaveTasksCommit")
	index := int32(1)
	//var files []string
	db := NewDb(taskFolder + "/data.db")
	if db == nil {
		return ;
	}
	defer db.Close()

	kvs := make(map[string][]byte);
	for _, task := range ts {
		task.ID = index;
		bytes, err := proto.Marshal(task)
		if err != nil {
			break
		}
		index++
		kvs[Int32ToHexString(task.ID)] = bytes
	}

	SetStringValues(db, kvs)

	//db.Batch(func(tx *bolt.Tx) error {
	//	b := tx.Bucket([]byte("Client"))
	//	if(b == nil){
	//		b, _ = tx.CreateBucket([]byte("Client"))
	//	}
	//	for _, task := range ts {
	//		task.ID = index;
	//		bytes, err := proto.Marshal(task)
	//		if err != nil {
	//			break
	//		}
	//		//fileName := fmt.Sprintf("%s/TASK_%08d", taskFolder, index)
	//		index++
	//		//WriteBytesSafe(fileName, bytes)
	//		b.Put(Int32ToBytes(task.ID), bytes);
	//		//files = append(files, fileName)
	//	}
	//	return nil
	//})

	return
}

