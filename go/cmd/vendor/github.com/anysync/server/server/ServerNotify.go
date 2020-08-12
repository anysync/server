// Copyright (c) 2020, Yanbin (Henry) Zheng <ybzheng@gmail.com>
// All rights reserved.
//
// Use of this source code is governed by a AGPLv3 license that can be
// found in the LICENSE file.

package server

import (
	client "github.com/anysync/server/client"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/request"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/golang/protobuf/proto"
	"golang.org/x/net/context"
	"golang.org/x/sync/syncmap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/peer"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
	utils "github.com/anysync/server/utils"
)

type remoteserver struct{}

var _notificationMap *syncmap.Map

func init() {
	_notificationMap = new(syncmap.Map) // cmap.New();

}

func RegisterServer(grpcS *grpc.Server) {
	utils.RegisterSyncResultServer(grpcS, &remoteserver{})
}

//At main server, receives a request from GO client
func (s *remoteserver) Subscribe(in *utils.UserRequest, stream utils.SyncResult_SubscribeServer) error {
	//utils.Infof("Add new watcher, user:%s, deviceID: %d, device:%s", in.UserID, in.DeviceID, in.DeviceName)
	deviceID := fmt.Sprintf("%d", in.DeviceID)
	b, user := Authenticate(in.UserID, in.Auth, in.DeviceID, in.Time)
	if !b || user == nil {
		utils.Debug("Time:", in.Time, "; in.Auth:", in.Auth, "; userID:", in.UserID)
		return errors.New("auth failed in subscribe")
	} else {
		utils.Debug("Authenticated user: ", in.UserID)
	}

	ctx := stream.Context()

	if p, ok := peer.FromContext(ctx); ok{
		ip := p.Addr.String();
		n := time.Now()
		user.LastLogin = uint32(n.Unix());
		user.LastIP = ip;
		UpdateUserAtRootServer(user, false)
	}

	if tmp, ok := _notificationMap.Load(in.UserID); ok {
		s := tmp.(map[string]utils.SyncResult_SubscribeServer)
		s[deviceID] = stream
		_notificationMap.Store(in.UserID, s)
	} else {
		s := make(map[string]utils.SyncResult_SubscribeServer)
		s[deviceID] = stream
		_notificationMap.Store(in.UserID, s)
	}

	for {
		select {
		case <-ctx.Done():
			utils.Infof("Connection done. UserID: %s, device: %s", in.UserID, deviceID)
			RemoveDeviceSubscriber(in.UserID, deviceID)
			return ctx.Err()
		}
	}
}

func RemoveDeviceSubscriber(user, device string) {
	if tmp, ok := _notificationMap.Load(user); ok {
		s := tmp.(map[string]utils.SyncResult_SubscribeServer)
		delete(s, device)
		if len(s) == 0 {
			utils.Debugf("Remove listener device: %s", device)
			_notificationMap.Delete(user)
		} else {
			utils.Debugf("Remove listener user (no active device left): %s", user)
			_notificationMap.Store(user, s)
		}
	}
}

func NotifySubscribers(user, deviceSelf, action string, data map[string][]byte, notifySelfOnly bool) {
	utils.Debug("deviceSelf:", deviceSelf, "; notificationMap::", _notificationMap)

	if tmp, ok := _notificationMap.Load(user); ok {
		s := tmp.(map[string]utils.SyncResult_SubscribeServer)
		utils.Debug("Devices.len:", len(s))
		now := uint32(time.Now().Unix())
		toBreak := false
		for device, stream := range s {
			if device == deviceSelf {
				if !notifySelfOnly {
					continue
				} else {
					toBreak = true
				}
			} else if notifySelfOnly {
				continue
			}
			utils.Debug("To send out notification to ", user, "; device:", device, "; action:", action)
			err := stream.Send(&utils.ActionResponse{
				Time:     now,
				User:     user,
				DeviceID: uint32(utils.ToInt(device)),
				Action:   action,
				Data:     data,
			})
			if err != nil {
				utils.Infof("Connection error occurred, user: %s, device: %s", user, device)
				RemoveDeviceSubscriber(user, device)
			}

			if toBreak {
				break
			}
		}
	}
}

func (s *remoteserver) SendData(ctx context.Context, in *utils.UserRequest) (*utils.ActionResponse, error) {
	utils.Debug("Enter SendData, user: ", in.UserID, "; action: ", in.Action, "; device: ", in.DeviceID, "; in.pass: ", in.Auth)
	defer utils.Debug("Leave SendData, user: ", in.UserID, "; action: ", in.Action, "; device: ", in.DeviceID, "; in.pass: ", in.Auth)

	if in.Action != "ShareAction" && in.Action != "serverShareFolder" && in.Action != "readLogSince" && in.Action != "loadRowsFromLogFile" &&
		in.Action != "getShareInitServerSide" && in.Action != "saveClientsDatFile" {
		b, u := Authenticate(in.UserID, in.Auth, in.DeviceID, in.Time)
		if(!b || u == nil) {
			utils.Debug("SendData auth failed.")
			return utils.NewActionResponseWithError(utils.ERROR_CDOE_BAD_AUTH), errors.New("auth failed")
		}
	}

	if in.Action != "getAuthorization" && in.Action !=  "getUploadAuth" && in.Action != utils.ACTION_ACK {
		if !utils.IsVersionOk(in.Version) {
			utils.Debug("Wrong version:", in.Version)
			return utils.NewActionResponseWithError(utils.ERROR_CODE_BAD_VERSION), errors.New("wrong version")
		}


	}
	response := utils.ActionResponse{
		User:     in.UserID,
		DeviceID: in.DeviceID,
	}
	response.Data = make(map[string][]byte)
	user, errCode := GetUserAccountByID(utils.ToInt(in.UserID))
	if errCode != 0 {
		return utils.NewActionResponseWithError(errCode), errors.New("error")
	}
	if user == nil {
		return utils.NewActionResponseWithError(utils.ERROR_CDOE_BAD_AUTH), errors.New("no user found")
	}
	utils.Debug("SendData.user is", user.Email, "; id:", user.ID, "; action is", in.Action)
	if needToSubscribe := checkSubscribeAgain(in.UserID, in.DeviceID); needToSubscribe {
		response.Data[utils.SUBSCRIBE] = []byte("true")
	}
	if in.Action == "key" {
		key := []byte(in.Data["key"])
		file := utils.GetUserRootOnServerByID(user.ID) + "/data/master.keys"
		utils.Debug("~~~~~~~~~~~~~~~ Write data to ", file, "; recved string size: ", len(key))
		utils.WriteBytesSafe(file, key)
	} else if in.Action == "device" {
		//user.Devices[fmt.Sprintf("%d", in.DeviceID)] = in.DeviceName
		user.MaxID ++;
		UpdateUserAtRootServer(user, false)
	} else if in.Action == "saverepos" {
		utils.Debug("Repos, user: ", in.UserID, "; Task.len: ", len(in.Tasks))
		filesizes := GetLogSizes(in.Tasks, in.UserID)
		n := len(in.Tasks)
		for i := 0; i < n; i++ {
			task := in.Tasks[i]
			client.ExecuteTask(task, false,  in.UserID, true)
		}
		UpdateServerBinTasks(in.Tasks, in.UserID, filesizes, utils.REPO_SHARE_STATE_ALL)
		SaveClientsDatFile(in.UserID, fmt.Sprintf("%d", in.DeviceID), 0, "", 0, false)
	} else if in.Action == "getPubkeys" {
		users := string(in.Data["users"])
		tokens := strings.Split(users, ",")
		response.Data = make(map[string][]byte)
		utils.Debug("getPubkeys for user: ", users)
		for _, t := range tokens {
			u, err := GetUserAccountBy(t, true)
			if err == 0 && u != nil {
				utils.Debug("pub key  found for user: ", t, "; pubKey is ", fmt.Sprintf("%x",u.PubKey))
				response.Data[t] = u.PubKey
			} else {
				utils.Debug("pub key not found for user: ", t)
			}
		}
	} else if in.Action == "getUserInfo" {
		owner := string(in.Data["user"])
		utils.Debug("in.UserID:", in.UserID, "; owner:", owner)
		if owner != "" {
			var errCode utils.AsErrorCode
			user, errCode = GetUserAccountByID(utils.ToInt(in.UserID))
			if errCode != 0 {
				return utils.NewActionResponseWithError(errCode), errors.New("user does not exist")
			}
		}
		response.Data["email"] = []byte(user.Email)
		response.Data["name"] = []byte(user.Name)
		response.Data["type"] = []byte(fmt.Sprintf("%d", user.AccountType))
		response.Data["quota"] = []byte(fmt.Sprintf("%d", user.Quota))
		response.Data["prefix"] = []byte(user.Prefix)
		response.Data["bucket"] = []byte(user.Bucket)
		k := GetMainServerAuthKey()
		h := utils.NewHmac(k[:])
		uid := fmt.Sprintf("%d", user.ID)
		h.Write([]byte(uid))
		hash := h.Sum(nil)
		response.Data["uid"] = []byte(fmt.Sprintf("%d.%x", user.ID, hash))
		response.Data["server"] = []byte(user.Server)


	} else if in.Action == "readLogSince" {
		readLogSince(in, &response)
	} else if in.Action == "loadRowsFromLogFile" {
		loadRowsFromLogFile(in, &response)
	} else if in.Action == "saveClientsDatFile" {
		end := utils.ToInt(string(in.Data["end"]))
		SaveClientsDatFile(in.UserID, string(in.Data["device"]), end, string(in.Data["id"]), int64(utils.ToInt(string(in.Data["size"]))), true)
	}else if in.Action ==  utils.ACTION_ACK {
		d := map[string][]byte{
			"user":   []byte(fmt.Sprintf("%d", user.ID)),
			"type":   []byte(fmt.Sprintf("%d", user.AccountType)),
			"quota":  []byte(fmt.Sprintf("%d", user.Quota)),
			"expiry": []byte(fmt.Sprintf("%d", user.Expiry)),
			"prefix": []byte(user.Prefix),
			"bucket": []byte(user.Bucket),
			"order":  []byte(user.OrderID),
			"email": []byte(user.Email),
		}
		response.Data = d;

	} else if in.Action == "getUploadAuth" {
		if err := presignRequest(user, in, response); err != nil{
			return utils.NewActionResponseWithError(utils.ERROR_CDOE_BAD_AUTH), err
		}

	} else if in.Action == "updateMeta" {
		utils.UpdateMeta(in.UserID, string(in.Data["hash"]), string(in.Data["id"]))


	}
	go sendDataStatus(ctx, in) // http://dahernan.github.io/2015/02/04/context-and-cancellation-of-goroutines/

	return &response, nil
}




func presignRequest(user *utils.UserAccount, in *utils.UserRequest, response utils.ActionResponse) error{
	u := string(in.Data["=url"]);
	method := string(in.Data["=m"])
	prefix := string(in.Data["=pre"])
	remoteNameCode := string(in.Data["=c"])
	if(u == "" || method == "" || remoteNameCode == ""){
		return errors.New("invalid url or method");//invalid
	}
	s := utils.LoadAppParams().GetStorage(remoteNameCode)
	if s == nil {
		return errors.New("invalid storage"); //invalid
	}
	utils.Debug("Received url: ", u)  //  http://172.16.118.149:65064/anysyncnet1
	urlObj, _ := url.Parse(u)
	path := urlObj.Path // "/anysyncnet1/test"
	path = path[1:]
	pos := strings.Index(path, "/" )
	key := ""
	bucket := ""
	if pos > 0 {
		key = path[pos+1:]
		bucket = path[0:pos]
	}else{
		bucket = path;
	}
	utils.Debug("bucket:", bucket, "; method:", method, "; prefix:", prefix, "; objectKey:", key, "; userprefix:", user.Prefix)
	klen := len(key)
	if(klen > 0 && !strings.HasPrefix(key, user.Prefix)){
		utils.Debug("Invalid request, key:", key , "; user.prefix:",  user.Prefix)
		return errors.New("invalid prefix")
	}
	if utils.IS_OFFICIAL_MAIN_SERVER && klen == 0 {
		return errors.New("invalid request")
	}

	config := aws.NewConfig().
		WithHTTPClient(getHttpClient()).
		WithMaxRetries(1).
		WithEndpoint(s.EndPoint).WithRegion(s.Region).WithCredentials(credentials.NewStaticCredentials(s.Key, s.Secret, "")).


		WithS3ForcePathStyle(true) //MUST HAVE
	sess, err := session.NewSession(config)
	// Create S3 service client
	svc := s3.New(sess)
	// Ensure that response body is drained
	svc.Handlers.Complete.PushBack(func(req *request.Request) {
		defer req.HTTPResponse.Body.Close()
		io.Copy(ioutil.Discard, req.HTTPResponse.Body)
	})



	var r *request.Request;
	if( len(prefix) > 0){
		r, _ = svc.ListObjectsRequest(&s3.ListObjectsInput{
			Bucket: aws.String(bucket),
			Prefix: aws.String(prefix),
		})

	}else if method == "GET" {
		r, _ = svc.GetObjectRequest(&s3.GetObjectInput{
			Bucket: aws.String(bucket),
			Key:    aws.String(key),
		})
	}else if method == "PUT"{
		r, _ = svc.PutObjectRequest(&s3.PutObjectInput{
			Bucket: aws.String(bucket),
			Key:    aws.String(key),
		})
	}else if method == "HEAD"{
		r, _ = svc.HeadObjectRequest(&s3.HeadObjectInput{
			Bucket: aws.String(bucket),
			Key:    aws.String(key),
		})
	}else if method == "DELETE"{
		r, _ = svc.DeleteObjectRequest(&s3.DeleteObjectInput{
			Bucket: aws.String(bucket),
			Key:    aws.String(key),
		})
	}else{
		return errors.New("invalid HTTP method")
	}

	r.HTTPRequest.URL = urlObj
	r.HTTPRequest.Method = method
	r.NotHoist = false;

	var url string;
	var headers http.Header;
	if(len(key) == 0){
		//this way signs both header and body
		r.Handlers = svc.Handlers.Copy()
		//utils.Info("Handlers.len:", r.Handlers.Sign.Len(), "; handlers:", r.Handlers.Sign)
		r.Handlers.Sign.Run(r)
		url = r.HTTPRequest.URL.String()
		headers = r.HTTPRequest.Header
	}else {
		//this one only signs the header part
		url, headers, err = r.PresignRequest(45 * time.Minute)
		if err != nil {
			utils.Warn("Error signing:", err)
		}
	}
	utils.Debug("signedurl:", url, "; \nheaders:", headers)
	response.Data["=url"] = []byte(url);
	for name, values := range headers {
		response.Data[name] = []byte(strings.Join(values, "|"))
	}
	return nil
}

var s3HttpClient * http.Client;
func getHttpClient()* http.Client{
	if s3HttpClient != nil{
		return s3HttpClient
	}
	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout: 30 * time.Second,
		}).DialContext,
		DisableCompression:  false,
		DisableKeepAlives:   false,
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 100,
		IdleConnTimeout:     10 * time.Minute,
		TLSHandshakeTimeout: 30 * time.Second}
	s3HttpClient = &http.Client{Timeout: 0, Transport: transport}
	return s3HttpClient;
}
func checkSubscribeAgain(userID string, deviceID uint32) bool {
	if tmp, ok := _notificationMap.Load(userID); ok {
		s := tmp.(map[string]utils.SyncResult_SubscribeServer)
		d := fmt.Sprintf("%d", deviceID)
		for device := range s {
			if device == d {
				utils.Debug("User:", userID, "; device:", deviceID, " has lost listener connection. Tell it to reconnect.")
				return false
			}
		}
	}
	return true
}

func Authenticate(userID, Password string, DeviceID, Time uint32) (bool, *utils.UserAccount) {
	if !utils.IsInteger(userID) {
		utils.Error("Wrong userID: ", userID)
		return false, nil
	}
	user, err := GetUserAccountBy(userID, true)
	if err != 0 {
		utils.Debug("DB not working", userID)
		return false, nil
	}
	if user == nil {
		utils.Debug("Authenticate. UserID does not exist: ", userID)
		return false, nil
	}
	sig := utils.CreateSignatureString(user.AccessToken, userID, Time)
	ret := sig == Password
	utils.Debug("Auth. user: ", userID, "; AuthResult: ", ret, "; device:", DeviceID,
		"; token: ", Password, "; user.AToken:", hex.EncodeToString(user.AccessToken),
		"; time:", Time, "PubKey:", Password, "; sig:", sig, "; auth.ret:", ret)

	return ret, user
}

func (s *remoteserver) RetrieveAccessToken(ctx context.Context, in *utils.UserRequest) (*utils.ActionResponse, error) {
	return nil, nil
}

//resetgetall notify client
func PrepareZipFileForDownload(in *utils.UserRequest) {
	mode := in.Data["mode"]
	includeAll := len(mode) == 0   //if it's not includeAll, then only include server.bin file
	fileName := utils.CreateZipForUser(in.UserID, includeAll)

	repo := utils.GetUserRootOnServer(in.UserID)
	newFileSize := utils.FileSize(repo + "/data/server.bin")

	data := map[string][]byte{
		"file":   []byte(fileName),
		"offset": []byte(fmt.Sprintf("%d", newFileSize)),
	}
	utils.Debug("To notify subscriber to download: ", fileName, "; FileSize: ", utils.FileSize(utils.GetRootOnServer()+"/tmp/"+fileName))
	NotifySubscribers(in.UserID, fmt.Sprintf("%d", in.DeviceID), utils.ACTION_DOWNLOAD, data, true)
}

func UpdateUserAction(inData map[string][]byte) {
	udata := inData["user"]
	user := utils.UserAccount{}
	isNew := string(inData["isNew"]) == "true"
	if proto.Unmarshal(udata, &user) == nil {
		user.LastLogin = uint32(time.Now().Unix())
		UpdateUserInDb(&user, isNew)
	}

	if string(inData["notify"]) == "true" {
		uid := fmt.Sprintf("%d", user.ID)
		data := map[string][]byte{
			"type":   []byte(fmt.Sprintf("%d", user.AccountType)),
			"quota":  []byte(fmt.Sprintf("%d", user.Quota)),
			"prefix": []byte(user.Prefix),
			"bucket": []byte(user.Bucket),
			"user":  []byte(uid),
			"order":  []byte(user.OrderID),
			"expiry": []byte(fmt.Sprintf("%d", user.Expiry)),
		}
		NotifySubscribers(uid, "", utils.ACTION_ACCT_TYPE_CHANGE, data, false)
	}
}

func GetUserAction(in *utils.UserRequest) *utils.UserAccount {
	if name, ok := in.Data["name"]; ok {
		return doGetUserAccount(string(name))
	} else {
		uid := 0
		if udata, ok := in.Data["user"]; ok {
			utils.Debug("GetUserAction, user:", string(udata))
			uid = utils.ToInt(string(udata))
			u := doGetUserAccountByID(uid)
			return u
		}
		return nil
	}
}

var verfiyMutex = utils.NewKmutext();// &sync.Mutex{}

func VerifyRepo(in *utils.UserRequest) {
	hash := string(in.Data["hash"])
	userID := in.UserID;
	verfiyMutex.Lock(userID)
	defer verfiyMutex.Unlock(userID)
	user, errCode := GetUserAccountBy(userID, true);
	if errCode != 0 {
		return;
	}
	userRoot := utils.GetUserRootOnServer(userID)
	dbFile := userRoot + "/objects/verified.db";
	verifyDb := utils.NewDb(dbFile)//,  0600, nil)
	defer verifyDb.Close();


	err := DeepVerifyOnServer(verifyDb, user, hash)
	status := "OK"
	code := 200
	if err == nil {
		utils.Debug("Verified repo!")
	} else {
		status = err.Msg // fmt.Sprintf("%v", err)
		code = err.Code
	}
	data := map[string][]byte{
		"status": []byte(status),
		"code":   []byte(fmt.Sprintf("%d", code)),
		"folder": []byte(hash),
	}
	if err != nil && err.Data != nil {
		utils.Debug("err.Data: ", err.Data)
		utils.MapAddAll2(data, err.Data)
		utils.Debug("Now data: ", data)
	}
	NotifySubscribers(in.UserID, fmt.Sprintf("%d", in.DeviceID), utils.ACTION_VERIFY, data, true)
}

func readLogSince(in *utils.UserRequest, response *utils.ActionResponse) {
	offset := utils.ToInt(string(in.Data["offset"]))
	user := in.UserID

	binLog := NewServerBinLog(user, "0", 0)
	binLog.BinFileName = utils.GetUserRootOnServer(user) + "/data/server.bin"
	utils.Debug("Enter main server' readLogSince. offset:", offset, "; user:", in.UserID, ";binFile:", binLog.BinFileName)

	repoTree := utils.GetUserRootOnServer(user) + "tree/"
	binLog.readLogSince(repoTree, uint32(offset), 0, nil)
	r := utils.BinLogResponse{}
	r.ServerChanges = binLog.serverChanges
	r.FolderUpdates = binLog.FolderUpdates
	utils.Debug("In readLogSince, serverChanges.len:", len(binLog.serverChanges), "; folderUpdates.len:", len(binLog.FolderUpdates))
	if data, err := proto.Marshal(&r); err == nil {
		utils.Debug("ServerNotify.readLogSince, set binlog data")
		response.Data["binlog"] = data
	} else {
		utils.Debug("ServerNotify.readLogSince, error occurred")
		utils.Debug("Error:", err)
	}
}
func loadRowsFromLogFile(in *utils.UserRequest, response *utils.ActionResponse) {
	owner := string(in.Data["owner"])
	binLog := NewServerBinLog(owner, "0", 0) //ServerBinLog);
	folder := utils.ModifiedFolder{}
	proto.Unmarshal(in.Data["folder"], &folder)
	updates := new(utils.ServerFolderUpdates)
	var b bool
	rowCount := 0
	if updates, b = binLog.loadRowsFromLogFile(&folder, owner, updates, &rowCount); b {
		r := utils.BinLogResponse{}
		r.FolderUpdates = binLog.FolderUpdates
		r.FolderUpdates[folder.FolderHash] = updates
		utils.Debug("In loadRowsFromLogFile, folderHash:", folder.FolderHash)
		if data, err := proto.Marshal(&r); err == nil {
			response.Data["binlog"] = data
		} else {
			utils.Debug("Error:", err)
		}
	}
}

var userSyncLock = utils.NewKmutext() // &sync.Mutex{}

//At main server, receives a request from GO client
func (s *remoteserver) GetSyncResult(ctx context.Context, in *utils.ModifiedData) (*utils.ServerSyncResponse, error) {
	utils.Debug("Enter GetSyncResult, in.User:", in.User)
	if !utils.IsVersionOk(in.Version){
		utils.Debug("Wrong version:", in.Version)
		return nil, errors.New("wrong version")
	}


	b, userObj := Authenticate(in.User, in.Auth, in.DeviceID, in.Time)
	if !b || userObj == nil {
		return nil, errors.New("auth failed")
	}
	UpdateUserAtRootServer(userObj, false)
	utils.Debug("update user returned")
	user := in.User
	originator := ""
	if u, ok := in.Headers["originator"]; ok && u != "" && user != u { //handle shared folder by others, the request contains owner
		originator = in.User
		user = u
	}
	now := uint32(time.Now().Unix());
	if(now >= (userObj.Expiry + 86400 * 2) ){
		utils.Info("Account already expired:", userObj.ID)
		return nil, errors.New("account expired") ;
	}
	utils.Debug("to call userSyncLock. User:", user)
	userSyncLock.Lock(user)
	defer userSyncLock.Unlock(user)
	utils.Debug("In GetSyncResult, objects.len:", len(in.Objects), ";folders.len:", len(in.Folders))
	DoSaveObjectsToFileOnServer(in.Objects, user, utils.GetUserRootOnServer(user), true)
	utils.Debug("#################GetSyncResultInvoked.header.size: ", in.Headers["size"])
	syncData, binLog := ProcessAtRemoteServer(user, originator, in.DeviceID, in.Headers, in.Folders)
	//binLog.WriteTasks = improvedTasks(binLog.WriteTasks)
	hasNew := len(in.Folders) > 0
	go work(ctx, binLog, syncData.Objects, in.Notify, user, originator, hasNew) // http://dahernan.github.io/2015/02/04/context-and-cancellation-of-goroutines/
	if needToSubscribe := checkSubscribeAgain(user, in.DeviceID); needToSubscribe {
		syncData.Props = make(map[string]string)
		syncData.Props[utils.SUBSCRIBE] = "true"
	}

	return &syncData, nil
}

func (s *remoteserver) CallAction(ctx context.Context, in *utils.UserRequest) (*utils.ActionResponse, error) {
	if in.Action != utils.ACTION_GET_USER {
		b, u := Authenticate(in.UserID, in.Auth, in.DeviceID, in.Time);
		if (!b || u == nil) {
			return nil, errors.New("auth failed")
		}
	}
	utils.Debug("Enter CallAction, user ", in.UserID, "; action:", in.Action)
	response := utils.ActionResponse{
		User:     in.UserID,
		DeviceID: in.DeviceID,
	}
	response.Data = make(map[string][]byte)
	if needToSubscribe := checkSubscribeAgain(in.UserID, in.DeviceID); needToSubscribe {
		response.Data[utils.SUBSCRIBE] = []byte("true")
	}
	if in.Action == utils.ACTION_RESET_GET_ALL {
		go PrepareZipFileForDownload(in)
	} else if in.Action == utils.ACTION_VERIFY {
		go VerifyRepo(in)
	} else if in.Action == utils.ACTION_ADD_USER {
		go UpdateUserAction(in.Data)
	} else if in.Action == utils.ACTION_GET_USER {
		u := GetUserAction(in)
		if data, err := proto.Marshal(u); err == nil {
			response.Data["user"] = data
		} else {
			utils.Debug("Error:", err)
		}

	}
	return &response, nil
}

func sendDataStatus(ctx context.Context, in *utils.UserRequest) error {
	select {
	case <-ctx.Done():
		utils.Debug("Done ----------------------- ")
		if in.Action == "getShareInitServerSide" {
			shareID := string(in.Data["id"])
			originator := string(in.Data["originator"])
			utils.Debug("To call SaveClientsDatFile. shareID:", shareID, "; deviceID:", in.DeviceID, "; originator:", originator)
			SaveClientsDatFile(originator, fmt.Sprintf("%d", in.DeviceID), 0, shareID, 0, true)
		}
		return ctx.Err()
	}
}

func work(ctx context.Context, binLog *ServerBinLog, objects map[string][]byte, notify bool, user, shareChangeOriginator string, hasNew bool) error {
	defer userSyncLock.Unlock(utils.ToInt(user))

	select {
	case <-ctx.Done():
		//fmt.Println("Done ----------------------- ")
		//utils.Debugf("BinLog info: %s", binLog.Info());

		ResponseDelivered(binLog, objects, shareChangeOriginator)
		if notify && hasNew {
			//if(binLog.shareState == utils.REPO_SHARE_STATE_SHARE){
			//	data := make(map[string][]byte);
			//	for _, folder := range binLog.clientChanges{
			//		shareFolders := utils.GetShareFoldersOnServer(binLog.User, folder.FolderHash);
			//		if(shareFolders != nil) {
			//			subPath := utils.HashToPath(folder.FolderHash)
			//			data["hash"] = []byte(folder.FolderHash)
			//			processed := make(map[string]bool)
			//			for _, shareFolder := range shareFolders {
			//				if (shareFolder.MemberKeys != nil) {
			//					for user := range shareFolder.MemberKeys {
			//						if(utils.SetContains(processed, user)){
			//							continue;
			//						}
			//						processed[user] = true;
			//						size := utils.FileSize(utils.GetUserRootOnServer(user) + "share/" + subPath + "/data/server.bin")
			//						data["size"] = []byte(fmt.Sprintf("%d", size))
			//						NotifySubscribers(user, "", utils.ACTION_UPDATE, data, false)
			//					}
			//				}
			//			}
			//		}
			//	}
			//}else {
			size := utils.FileSize(binLog.BinFileName)
			data := make(map[string][]byte)
			data["size"] = []byte(fmt.Sprintf("%d", size))
			utils.Debug("######################## server.bin.size: ", size)
			NotifySubscribers(binLog.User, binLog.DeviceID, utils.ACTION_UPDATE, data, false)
			//}
		}
		utils.Debug("Work thread returned  ----------------------- \n\n\n\n")
		return ctx.Err()
	}
}


