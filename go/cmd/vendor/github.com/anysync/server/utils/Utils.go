// Copyright (c) 2020, Yanbin (Henry) Zheng <ybzheng@gmail.com>
// All rights reserved.
//
// Use of this source code is governed by a AGPLv3 license that can be
// found in the LICENSE file.
package utils

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/djherbis/times"
	"github.com/golang/protobuf/proto"
	"github.com/kardianos/osext"
	"golang.org/x/net/context"
	"golang.org/x/sync/syncmap"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode"
)

func PutUint32(b []byte, start int, v uint32) {
	b[start] = byte(v >> 24)
	b[start+1] = byte(v >> 16)
	b[start+2] = byte(v >> 8)
	b[start+3] = byte(v)
}
func PutInt32(b []byte, start int, v int32) {
	b[start] = byte(v >> 24)
	b[start+1] = byte(v >> 16)
	b[start+2] = byte(v >> 8)
	b[start+3] = byte(v)
}
func PutInt(b []byte, start int, v int) {
	b[start] = byte(v >> 24)
	b[start+1] = byte(v >> 16)
	b[start+2] = byte(v >> 8)
	b[start+3] = byte(v)
}
func PutUint64(b []byte, start int, v uint64) {
	_ = b[7] // early bounds check to guarantee safety of writes below
	b[start] = byte(v >> 56)
	b[start+1] = byte(v >> 48)
	b[start+2] = byte(v >> 40)
	b[start+3] = byte(v >> 32)
	b[start+4] = byte(v >> 24)
	b[start+5] = byte(v >> 16)
	b[start+6] = byte(v >> 8)
	b[start+7] = byte(v)
}

func Uint32ToBytes(i uint32)[]byte{
	ret := make([]byte, 4)
	PutUint32(ret, 0, i)
	return ret;
}
func Int32ToBytes(i int32)[]byte{
	ret := make([]byte, 4)
	PutInt32(ret, 0, i)
	return ret;
}

func Int32ToHexString(i int32)string{
	return strconv.FormatInt(int64(i), 16);
}
func ToInt(text string)int{
	i, _:= strconv.Atoi(text)
	return i;
}

func ToUint32(text string)uint32{
	i, _:= strconv.Atoi(text)
	return uint32(i);
}

func ToInt64(text string)(int64, error){
	return strconv.ParseInt(text, 10, 0)
}

func IntStringToPath(itext string) string {
	i, _ := strconv.Atoi(itext)
	return IntToPath(i)
}

func IntToPath(i int) string {
	return fmt.Sprintf("%d/%d/%d/", i%997, i%983,  i)
}

func FromHex(text string) []byte {
	ret, _ := hex.DecodeString(text)
	return ret
}
func ToHex(bs []byte) string {
	return  hex.EncodeToString(bs)
}

func Int64ToBytes(i int64) []byte{
	bs := make([]byte, 8);
	binary.BigEndian.PutUint64(bs, uint64(i));
	return bs;
}

func IntToBytes(i int) []byte{
	bs := make([]byte, 4);
	binary.BigEndian.PutUint32(bs, uint32(i));
	return bs;
}

func BytesToInt64( bs []byte) int64{
	return int64(binary.BigEndian.Uint64(bs))
}
func BytesToUInt32( bs []byte) uint32{
	return uint32(binary.BigEndian.Uint32(bs))
}
func SetContains(m map[string]bool, key string) bool {
	if(m == nil) {
		return false;
	}
	if _, ok := m[key]; ok {
		return true
	} else {
		return false
	}
}

func IsWindows() bool {
	return runtime.GOOS == "windows"
}

func IsLinux() bool {
	return runtime.GOOS == "linux"
}

func IsMac() bool {
	return runtime.GOOS == "darwin"
}

func IsInteger(s string) bool {
	for _, c := range s {
		if !unicode.IsDigit(c) {
			return false
		}
	}
	return true
}

func HashToPath(hash string) string {
	//Debug("HashToPath, hash: ", hash)
	if(len(hash)!=56){
		Error("Wrong hash:<", hash, ">")
		debug.PrintStack();
		os.Exit(1)
	}
	return fmt.Sprintf("%s/%s/%s/%s", hash[0:2], hash[2:4], hash[4:6], hash[6:])
}


/**
The built-in FileInfo struct does not contain absolute path! So this one was created.
*/
type RealFileInfo struct {
	AbsPath      string
	Name         string
	Permission   uint32
	LastModified uint32
	CreateTime   uint32
	Size         int64
	IsDir        bool
	IsFile       bool
	IsSymlink    bool
	Hash         string
	RelativePath string
	ParentHash   string
}

func CopyRealFileInfo(f *RealFileInfo) *RealFileInfo {
	fi := new(RealFileInfo)
	fi.Name = f.Name
	fi.Size = f.Size
	fi.IsDir = f.IsDir
	fi.IsFile = f.IsFile
	fi.Permission = f.Permission
	fi.IsSymlink = f.IsSymlink
	fi.AbsPath = f.AbsPath
	fi.Hash = f.Hash
	fi.LastModified = f.LastModified
	fi.CreateTime = f.CreateTime
	return fi
}

func NewRealFileInfo(f FileInfo, absPath string) *RealFileInfo {
	p := fromFileInfo(f)
	if p == 0 {
		return nil
	}
	fi := new(RealFileInfo)
	fi.Name = f.Name()
	fi.Size = f.Size()
	fi.IsDir = f.IsDir()
	fi.IsFile = f.Mode().IsRegular()
	fi.Permission = p
	fi.IsSymlink = IsSymlink(f)
	fi.AbsPath = absPath

	if t, err := times.Stat(absPath); err == nil {
		fi.LastModified = uint32(t.ModTime().Unix()) // uint32(f.ModTime().Unix());
		if t.HasBirthTime() {
			fi.CreateTime = uint32(t.BirthTime().Unix())
			//Debugf("FileHash:%s, birthTime:%d\n", fi.RemoteName, fi.CreateTime)
		} else {
			fi.CreateTime = fi.LastModified
		}
	}
	return fi
}

func IsFileModeDirectory(mode uint32) bool {
	return (mode & TYPE_MASK) == TYPE_DIRECTORY
}
func IsFileModeRepository(mode uint32) bool {
	return (mode & TYPE_MASK) == TYPE_REPOSITORY
}

func IsFileModeRegularFile(mode uint32) bool {
	return (mode & TYPE_MASK) == TYPE_FILE
}
func IsFileModePipe(mode uint32) bool {
	return (mode & TYPE_MASK) == TYPE_PIPE
}
func IsFileModeDeleted(mode uint32) bool {
	return (mode & TYPE_MASK) == TYPE_DELETED
}

func isDeletedFile(mode uint32) bool {
	if (mode & TYPE_MASK) != TYPE_DELETED {
		return false
	} else if (mode & 0x000F0000) == TYPE_DELETED_FILE {
		return true
	} else {
		return false
	}
}
func IsDeletedDirectory(mode uint32) bool {
	if (mode & TYPE_MASK) != TYPE_DELETED {
		return false
	} else if (mode & 0x000F0000) == TYPE_DELETED_DIRECTORY {
		return true
	} else {
		return false
	}
}

func SetFileModeDeleted(fileMode uint32) uint32 {
	if IsFileModeDirectory(fileMode) {
		fileMode = (fileMode & PERMISSION_MASK) | TYPE_DELETED_DIRECTORY
	} else {
		fileMode = (fileMode & PERMISSION_MASK) | TYPE_DELETED_FILE
	}
	return fileMode
}

func UndeleteDirectory(fileMode uint32) uint32 {
	fileMode = (fileMode & PERMISSION_MASK) | TYPE_DIRECTORY
	return fileMode
}
func fromFileInfo(fi FileInfo) uint32 {
	mode := fi.Mode()
	perm := uint32(mode.Perm())

	//ModeType = ModeDir | ModeSymlink | ModeNamedPipe | ModeSocket | ModeDevice    (https://golang.org/src/os/types.go)
	if fi.IsDir() {
		return TYPE_DIRECTORY | perm
	} else if mode.IsRegular() {
		return TYPE_FILE | perm
	} else if mode&os.ModeNamedPipe != 0 {
		return TYPE_PIPE | perm
	} else { //socket device named pipe
		return 0
	}
}

func Md5Text(text string) string {
	if len(text) == 0 {
		Debug("EmptyMD5==============================")
		//debug.PrintStack()
	}
	hasher := md5.New()
	hasher.Write([]byte(text ))
	return hex.EncodeToString(SumSuffix(hasher, GetHashSuffix()))
}
func Md5Bytes(text string) []byte {
	if len(text) == 0 {
		Debug("EmptyMD5==============================")
		//debug.PrintStack()
	}
	hasher := md5.New()
	hasher.Write([]byte(text))
	return SumSuffix(hasher, GetHashSuffix())
}

func CreateXattribKey(folderHash string, index uint32) string {
	return fmt.Sprintf("%s_%d", folderHash, index)
}

func UpdateAttribs(isClientSide bool, user string, folderHash string, index uint32, attribs map[string][]byte) {
	Debug("UpdateAttribs, user:", user, "; folderHash:", folderHash, "; index:", index, "; attribs.size:", len(attribs));//, "; attribs:", attribs)
	key := CreateXattribKey(folderHash, index);
	fattr := FileAttribs{}
	fattr.Attribs = attribs;
	bytes, err := proto.Marshal(&fattr)
	if err != nil {
		return;
	}
	//bytes, _ := json.Marshal(attribs)
	val := string(bytes);
	if (isClientSide) {
		NamesDbSetStringValue(key, val)
	} else {
		ServerNamesDbSetStringValue(user, key, val)
	}
}

type ModifiedFolderExt struct{
	ModifiedFolder;
	Repository *Repository;
	AbsPath string;
}


func NewModifiedFolder() *ModifiedFolder {
	mfolder := new(ModifiedFolder)
	mfolder.Rows = make(map[uint32]*ModifiedRow)
	return mfolder
}
func NewModifiedFolderExt() *ModifiedFolderExt {
	mfolder := new(ModifiedFolderExt)
	mfolder.Rows = make(map[uint32]*ModifiedRow)
	return mfolder
}

func (m *ModifiedRow) GetDisplayFileName() string {
	if m != nil {
		return GetDisplayFileName(m.FileName)
	}
	return ""
}

func GetDisplayFileName(fileName string)string{
	if(strings.HasPrefix(fileName, "/")) {
		encrypted, _ :=base64.StdEncoding.DecodeString(fileName[1:])
		fattr := FileAttribs{}
		fattr.Attribs = make(map[string][]byte)
		if proto.Unmarshal(encrypted, &fattr) == nil {
			prefix := ""; fileName := ""
			if p, ok := fattr.Attribs["x"] ; ok{
				prefix = string(p)
			}
			if encrypted, ok := fattr.Attribs["1"]; ok {
				folderHash := fmt.Sprintf("%x", fattr.Attribs["1h"])
				if shareKey, err := GetShareKey(folderHash); err == nil {
					bs := DecryptText(encrypted, &shareKey)
					if (bs != nil) {
						return string(bs)
					} else {
						fmt.Println("Cannot decrypt. Error: ", err)
						return ""
					}
				}else{
					fmt.Println("No share key")
					return ""
				}
			}else {
				encrypted := fattr.Attribs["0"]
				if _, ok := fattr.Attribs["0p"]; ok {
					privKey, _ := GetClientPrivKey();
					if bs, err := RsaDecrypt(string(privKey[:]), encrypted); err == nil {
						fileName = string(bs)
					}
				} else {
					if bs, err := DecryptUsingMasterKey(encrypted, nil); err == nil {
						fileName = string(bs)
					}
				}
			}
			return prefix + fileName;
		}else{
			fmt.Println("Cannot be unmarshalled: ", fileName)
		}
	}
	return fileName;
}

func GetShareKey(folderHash string)([32]byte, error) {
	var k [32]byte;
	sharedFolder := GetFirstShareFolderOnClient(folderHash)
	if(sharedFolder == nil){
		return k, errors.New("not found")
	}
	config := LoadConfig()
	key := sharedFolder.MemberKeys[config.User]
	if priv, err := GetClientPrivKey();err == nil {
		if es, err := hex.DecodeString(key); err == nil {
			if sharedKey, err := RsaDecrypt(priv, es); err == nil {
				copy(k[:], sharedKey);
				return k, nil;
			} else {
				return k, err;
			}
		}
	}
	return k, errors.New("cannot be decoded")

}

func SetFileNameKey(fileNameKey, fileNameValue, realFileName string, folderHash string,  key * [32]byte)string{
	if(strings.HasPrefix(fileNameValue, "/")) {
		encrypted,_ :=base64.StdEncoding.DecodeString( fileNameValue[1:])
		fattr := FileAttribs{}
		fattr.Attribs = make(map[string][]byte)
		if proto.Unmarshal(encrypted, &fattr) == nil {
			bs := EncryptText(realFileName, key)
			fattr.Attribs["1"] = bs;
			fattr.Attribs["1h"] = FromHex(folderHash);// []byte(fmt.Sprintf("%d", rowIndex));
			if bytes, err := proto.Marshal(&fattr); err == nil{
				text := "/" + base64.StdEncoding.EncodeToString(bytes)
				DbSetValue(fileNameKey, []byte(text))
				return text;
			}
		}
	}
	return "";
}
func EncryptFileNameKey(fileNameKey, realFileName string, folderHash string,  key * [32]byte)string{
	fattr := FileAttribs{}
	fattr.Attribs = make(map[string][]byte)

	bs := EncryptText(realFileName, key)
	fattr.Attribs["1"] = bs;
	fattr.Attribs["1h"] = FromHex(folderHash);// []byte(fmt.Sprintf("%d", rowIndex));

	if bytes, err := proto.Marshal(&fattr); err == nil{
		text := "/" + base64.StdEncoding.EncodeToString(bytes)
		DbSetValue(fileNameKey, []byte(text))
		return text;
	}
	return ""
}

func (m *ModifiedRow) SetDisplayFileNameForShareFolder(name, folderHash string, shareFolder *ShareFolder) {
	if m != nil {
		fattr := FileAttribs{}
		fattr.Attribs = make(map[string][]byte)
		bs, _ := EncryptUsingMasterKey([]byte(name))
		fattr.Attribs["0"] = bs;
		shareKey := shareFolder.GetShareFolderKey();
		if(shareKey != nil) {
			var key [32]byte
			copy(key[:], shareKey)
			bs := EncryptText(name, &key)
			fattr.Attribs["1"] = bs;
			fattr.Attribs["1h"] = FromHex(folderHash); // []byte(fmt.Sprintf("%d", rowIndex));
			if bytes, err := proto.Marshal(&fattr); err == nil {
				m.FileName = "/" + base64.StdEncoding.EncodeToString(bytes)
			}
		}
	}
}

func (m ShareFolder) GetShareFolderKey()[]byte{
	config := LoadConfig();
	if encrypted , ok := m.MemberKeys[config.User]; ok {
		privKey,_ := GetClientPrivKey();
		if es, err := hex.DecodeString(encrypted); err == nil {
			Debug("GetShareFolderKey, privkey:", hex.EncodeToString([]byte(privKey)))
			if bs, err := RsaDecrypt(privKey, es); err == nil {
				return bs;
			}
		}
	}
	return nil;
}

func (m *ModifiedRow) SetDisplayFileName(name string) {
	if m != nil {
		fattr := FileAttribs{}
		fattr.Attribs = make(map[string][]byte)
		bs, _ := EncryptUsingMasterKey([]byte(name))
		fattr.Attribs["0"] = bs;
		if bytes, err := proto.Marshal(&fattr); err == nil{
			m.FileName = "/" + base64.StdEncoding.EncodeToString(bytes)
		}
	}
}

func SetDisplayFileName(name string)string{
	fattr := FileAttribs{}
	fattr.Attribs = make(map[string][]byte)
	bs, _ := EncryptUsingMasterKey([]byte(name))
	fattr.Attribs["0"] = bs;
	if bytes, err := proto.Marshal(&fattr); err == nil{
		return "/" + base64.StdEncoding.EncodeToString(bytes)
	}
	return name;
}

func (m *ModifiedRow) AddFileNamePrefix(pre string) {
	if m != nil {
		if(strings.HasPrefix(m.FileName, "/")) {
			encrypted, _ :=base64.StdEncoding.DecodeString(m.FileName[1:])
			fattr := FileAttribs{}
			fattr.Attribs = make(map[string][]byte)
			if proto.Unmarshal(encrypted, &fattr) == nil {
				fattr.Attribs["x"] = []byte(pre)
				if bytes, err := proto.Marshal(&fattr); err == nil{
					m.FileName = "/" + base64.StdEncoding.EncodeToString(bytes)
				}else{
					Error("Couldn't marshal.", err)
					return;
				}
			}else{
				Error("Couldn't unmarshal")
				return;
			}
		}else {
			m.FileName = pre + m.FileName
		}
		UpdateConflictFileNameKey(m.Row)
	}
}

func GetRowCount(fileName string) uint32 {
	if !FileExists(fileName) {
		return 0
	}
	return uint32(FileSize(fileName) / FILE_INFO_BYTE_COUNT)
}

func FillMap(serverFolder *ModifiedFolder, fileNameMap map[string]*ModifiedRow) {
	for _, row := range serverFolder.Rows {
		fileNameMap[row.GetRowFileNameKey()] = row
		Debugf("Insert into fileNameMap, FileNameKey:%s", row.GetRowFileNameKey())
	}
}

func DeepCopy(r *ModifiedRow) *ModifiedRow {
	var newRow *ModifiedRow
	newRow = NewModifiedRow(false)
	*newRow = *r
	var bs []byte
	bs = make([]byte, len(r.Row))
	copy(bs, r.Row)
	newRow.Row = bs
	return newRow
}

func NewModifiedRow(createRowByteArray bool) *ModifiedRow {
	row := new(ModifiedRow)
	row.OperationMode = DEFAULT_OPERATION_MODE
	if createRowByteArray {
		row.Row = make([]byte, FILE_INFO_BYTE_COUNT)
	}
	return row
}



func (this ModifiedRow) GetRowFileNameKey() string {
	return fmt.Sprintf("%x", this.Row[4:4+FILE_NAME_KEY_BYTE_COUNT])
}

func (this ModifiedRow) GetRowIndex() uint32 {
	return binary.BigEndian.Uint32(this.Row)
}

func (this *ModifiedRow) SetRowIndex(index uint32) {
	PutUint32(this.Row, 0, index)
}

func (this ModifiedRow) GetIndexBinRow() *IndexBinRow {
	var bin = new(IndexBinRow)
	//Debugf("Row:%x\n", this.Row);
	bin.ReadBytes(this.Row, 0)
	return bin
}

func (this *ModifiedRow) GetOpMode() int32 {
	if this.OperationMode != DEFAULT_OPERATION_MODE {
		return this.OperationMode
	}
	row := this.GetIndexBinRow()
	this.OperationMode = int32(row.OperationMode)
	return this.OperationMode
}

func ResetUser(userID string){
	SetAppHome(userID);
	CurrentConfig = nil;
	ResetNamesDb();
}

func InitHashSuffix() (bool, string) {
	var hashSuffix string
	base := GetTopTreeFolder() + HashToPath(NULL_HASH)
	binFile := base + ".bin";
	if(!FileExists(binFile)){
		return false, "";
	}
	row := ReadBinFileForIndex(binFile,0)
	if(row == nil){
		return false, ""
	}
	hashSuffix = row.ToHashString();
	SetHashSuffix(hashSuffix)
	return true, hashSuffix
}

var hashsuffix string;
func GetHashSuffix()string{
	if(hashsuffix == ""){
		InitHashSuffix();
	}
	return hashsuffix;
}


func SetHashSuffix(value string) {
	hashsuffix = value // getTextHash(random)
}

//Turns /.../path1/path2.obj -> /.../path1
//or /.../path1/path2/ -> /.../path1
func RemoveLastUrlPathComponent(path string) string {
	pos := strings.LastIndex(path, "/");// string(filepath.Separator))
	//if pos <= 0 && IsWindows() {
	//	pos = strings.LastIndex(path, "\\");
	//}
	if pos <= 0 {
		return path
	}

	return path[0:pos]
}

//Returns /.../path1/path2.obj -> path2.obj
func GetLastUrlPathComponent(path string) string {
	pos := strings.LastIndex(path, "/")
	if pos <= 0 {
		return path
	} else {
		return path[pos+1:]
	}
}


//Remove last file path component
//Turns /.../path1/path2.obj -> /.../path1
//or /.../path1/path2/ -> /.../path1
func RemoveLastPathComponent(path string) string {
	return filepath.Dir(path)
}

//Get last file path component
//Returns /.../path1/path2.obj -> path2.obj
func GetLastPathComponent(path string) string {
	return filepath.Base(path);
}

func GenerateRandomHash() string {
	b := make([]byte, HASH_BYTE_COUNT)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}

func SendData(action, key, value string, tasks []*WriteTask)( *ActionResponse, error){
	Debug("Enter SendData, action is ", action)
	c, conn, err := NewGrpcClient()
	if err != nil {
		Warnf("did not connect: %v", err)
		return nil, err
	}
	defer conn.Close()

	config := LoadConfig();
	Debug("Send data, user: ", config.User , "; Token: ", hex.EncodeToString(CurrentAccessToken))
	data := make(map[string][]byte)
	request := UserRequest{
		UserID: config.User,
		Action: action,
		Data:   data,
	}
	SetUserRequestNow(&request, config.User, config.DeviceID) ;
	if(key != "") {
		data[key] = []byte(value);
	}
	if(tasks != nil){
		request.Tasks = tasks;
	}
	Debug("~~~~~~~~~~~~~~~~~~~~~~~~~~ To call c.SendData...")
	if r, err := c.SendData(context.Background(), &request); err != nil {
		Warn("Error occurred in SendData. Action:", action, "; Error:", err)
		return r, err;
	}else {
		if r.ErrorCode == uint32(ERROR_CODE_WRONG_SERVER) {
			ip := r.Data["ip"]
			if string(ip) != "" {
				Debug("Use new server IP:", string(ip))
				config.ServerIp = string(ip)
				return SendData(action, key, value, tasks)
			}
		}
		Debug("SendData returned...")
		return r,nil;
	}
}

func CallSendData(action string, tasks []*WriteTask, data map[string][]byte, data2 map[string][]byte, data3 map[string][]byte)( *ActionResponse, error){
	c, conn, err := NewGrpcClient()
	if err != nil {
		Warnf("did not connect: %v", err)
		return nil, err
	}
	defer conn.Close()

	config := LoadConfig();
	Debug("Enter CallSendData, action is ", action, "; user: ", config.User , "; deviceID:", config.DeviceID, "; Token: ", hex.EncodeToString(CurrentAccessToken))
	request := UserRequest{
		UserID: config.User,
		Action: action,
		DeviceID: ToUint32(config.DeviceID),
		Data:   data,
		Data2: data2,
		Data3: data3,
	}
	SetUserRequestNow(&request, config.User, config.DeviceID) ;
	if(tasks != nil){
		request.Tasks = tasks;
	}
	Debug("~~~~~~~~~~~~~~~~~~~~~~~~~~ To call c.SendData...request.userID:", config.User)
	if r, err := c.SendData(context.Background(), &request); err != nil {
		Warn("Error occurred in SendData. Action:", action, "; error:", err)

		return r, err;
	}else {
		Debug("SendData returned...")
		if(string(r.Data[SUBSCRIBE]) == "true"){
			Debug("SendData returned. subscribe is true")
			go Reconnect(false, false, nil)
		}

		return r,nil;
	}
}

//@return server ip, bucket path and other info
func GetUserInfo(user string)map[string][]byte{
	data := make(map[string][]byte)
	data["user"] = []byte(user)
	if response, err := CallSendData("getUserInfo", nil, data, nil, nil); err == nil {
		return response.Data;
		//return string(response.Data["server"]), string(response.Data["prefix"])
	}
	return nil
}


func SendSyncRequestToMainServer(in *ModifiedData, shareState int32, owner string) (*ServerSyncResponse, string) {
	config := LoadConfig()
	server := config.ServerAddress
	if config.ServerIp != ""{
		server = config.ServerIp
	}
	if(shareState == REPO_SHARE_STATE_SHARE){
		if(config.User != owner) { //it's a folder shared from other users, so send the request to the owner's server, which has bin and log files
			m := GetUserInfo(owner);
			if(m != nil){
				//Debug("It's shared folder, send request to share's owner server instead of its own server. owner server is ", s)
				server = string(m["server"])
			}
		}
	}
	// Set up a connection to the server.
	c, conn, err := NewGrpcClientWithServerAndDefaultPort(server)
	if err != nil {
		Warnf("did not connect: %v", err)
		return nil, "Couldn't connect to server"
	}
	defer conn.Close()
	in.User = config.User //("id", "1")
	in.DeviceID = ToUint32(config.DeviceID)
	in.Version = VERSION
	in.Server = config.ServerAddress

	in.Auth, in.Time = CreateSignature(in.User) //hex.EncodeToString(GetAccessToken());

	r, err := c.GetSyncResult(context.Background(), in)

	if r != nil  {
		if r.Code == int32(ERROR_CODE_WRONG_SERVER){
			ip := r.Objects["ip"]
			if string(ip) != ""{
			Debug("Use new server IP:", string(ip))
			config.ServerIp = string(ip)
			serverResponse, m := SendSyncRequestToMainServer(in, shareState, owner)
			return serverResponse, m
		}
		}else if r.Code == SERVER_CHANGE_TOO_MANY {
			return r, ""
		}

	}

	if err != nil {
		Debug("could not get result: ", err, "; result:", r)
		return nil, "Couldn't get result:" + err.Error();
	}else{
		if(r.Props[SUBSCRIBE] == "true"){
			Debug("SendSyncRequestToMainServer returned. subscribe is true")
			go Reconnect(false, false, nil)
		}
	}
	return r, ""
}

var FileNameToID = new(syncmap.Map)
func AddFileNameToID(fileName, id string){
	Debug("AddFileNameToID, fileName:", "<" + fileName + ">", "; ID:", id)
	FileNameToID.Store(fileName, id);
}
func GetFileID(fileMetaP string) (string, bool){
	pos := strings.Index(fileMetaP, "/objects");
	name := fileMetaP[pos+1:]
	Debug("To retrieve file name:", "<" + name + ">")
	if val, f := FileNameToID.Load(name); f {
		Debug("Found ID: ", val.(string))
		return val.(string), true;
	}
	return "", false;
}

func ClearFileNameToID(){
	FileNameToID = new(syncmap.Map)
}

func ToUnit( d int64) string {
	if(d < 1024) {
		return fmt.Sprintf("%d bytes", d);
	} else if ( d < 1024*1024) {
		return fmt.Sprintf("%.3f KB", float32(d)/float32(1000.0) );
	} else if ( d < 1024*1024*1024){
		return fmt.Sprintf("%.3f MB", float32(d)/float32(1000000.0));
	} else  {
		return fmt.Sprintf("%.3f GB",  float64(d)/float64(1000000000.0));
	}
}


func StringToUints(text string)[]uint32{
	tokens := strings.Split(text, ",")
	var ret []uint32;
	for _, token := range tokens{
		ret = append(ret, ToUint32(token))
	}
	return ret;
}

func UintsContains(arr []uint32, i uint32)bool{
	if(arr == nil){
		return false;
	}
	for _, val := range arr{
		if(val == i){
			return true;
		}
	}
	return false;
}

func MapAddAll2(dest map[string][]byte, m2 map[string][]byte) {
	if(m2 == nil){
		return;
	}
	for k, v := range m2 {
		dest[k] = v;
	}
}
func MapAddAll1(dest map[string]string, m2 map[string]string) {
	if(m2 == nil){
		return;
	}
	for k, v := range m2 {
		dest[k] = v;
	}
}

func GetAllShareFolderIncludes(shareFolders []*ShareFolder) []uint32{
	var includes []uint32;
	if(shareFolders == nil){
		return nil;
	}
	for _, shareFolder := range shareFolders{
		if len (shareFolder.Includes) > 0{
			ds := StringToUints(shareFolder.Includes)
			for _, d := range ds{
				if(!UintsContains(includes, d)){
					includes = append(includes, d)
				}
			}
		}else{
			//include all folder
			return nil;
		}
	}
	return includes;
}

//binFilePath: such as "1170431/tree/42/84/23/0f5f72d104585a4d7dbd1543fcf63a81be9731e47bef51be2b.bin"
func PathToHash(binFilePath string)string{
	l := len(binFilePath)
	hash := fmt.Sprintf("%s%s%s%s", binFilePath[l-63:l-61], binFilePath[l-60:l-58], binFilePath[l-57:l-55] , binFilePath[l - 54 :l - 4] ) // 4 is ".dat"
	return hash;
}

type ErrorWithCode struct {
	Msg    string
	Method string
	Retry  bool
	Code   int
	Fixable bool
	Data  map[string][]byte
}

func (e ErrorWithCode) Error() string {
	return fmt.Sprintf("%d - %s", e.Code, e.Msg)
}
func NewErrorWithCode(msg string, code int) * ErrorWithCode{
	return & ErrorWithCode{
		Msg: msg,
		Code: code,
	};
}

func CreateSignatureString(key []byte, user string,  date uint32)string{
	signingKey := getSigningKey(string(key), date, "")
	signature := getSignature(signingKey, fmt.Sprintf("%s\n%d", user , date))
	return signature;
}
func getSigningKey(secretKey string, t uint32, region string) []byte {
	date := sumHMAC([]byte("AWS4"+secretKey), []byte(fmt.Sprintf("%d", t)))
	regionBytes := sumHMAC(date, []byte(region))
	service := sumHMAC(regionBytes, []byte("s3"))
	signingKey := sumHMAC(service, []byte("aws4_request"))
	return signingKey
}
func getSignature(signingKey []byte, stringToSign string) string {
	return hex.EncodeToString(sumHMAC(signingKey, []byte(stringToSign)))
}
// sumHMAC calculate hmac between two input byte array.
func sumHMAC(key []byte, data []byte) []byte {
	hash := hmac.New(sha256.New, key)
	hash.Write(data)
	return hash.Sum(nil)
}

func Restart(toRescan bool)error{
	file, err := osext.Executable()
	if err != nil {
		return  err
	}
	if(toRescan){
		os.Args = append(os.Args, "rescan")
		Debug("To run ", file, ", args: ", os.Args)
		err = syscall.Exec(file, os.Args, os.Environ())
	}else {
		Debug("To run ", file, ", args: ", os.Args)
		err = syscall.Exec(file, os.Args, os.Environ())
	}
	if err != nil {
		Critical(err)
	}
	os.Exit(0);
	return  nil
}

type FileMeta struct {
	T int //Type
	//if T is FILE_PART_TYPE_REGURLAR, FILE_PART_TYPE_PACK, or FILE_PART_TYPE_CHUNK, it's cloud path;
	//for FILE_PART_TYPE_utils.PACK_ITEM , it's pack's file fileHash.
	//For HUGE file, it's FilePart array's path is chunk's file fileHash.
	P string //Path
	B string //Base
	F int64 //From
	S int64 //Size
	C int64 //CloudSize, file size on the cloud (after encryption and compression)
	K []string //Key
	//Chunks string
	//SData    * SecurityData

	//nonserializable
	fileHash     string
	folderHash   string
	relativePath string
	fileNameKey  string
	incomplete   int
	repository    * Repository
	lastModified uint32
	noStaging   bool
}

func(m FileMeta) GetLastModified() uint32{
	return m.lastModified;
}
func (m * FileMeta)SetLastModified(i uint32){
	m.lastModified = i;
}

func(m FileMeta)GetFileNameKey() string{
	return m.fileNameKey;
}

func(m * FileMeta)SetFileNameKey(h string){
	m.fileNameKey = h;
}

func(m * FileMeta)SetRelativePath(h string){
	m.relativePath = h;
}

func(m FileMeta)GetFolderHash() string{
	return m.folderHash;
}
func(m * FileMeta)SetFolderHash(h string){
	m.folderHash = h;
}

func(m FileMeta)GetFileHash() string{
	return m.fileHash;
}
func(m * FileMeta)SetFileHash(h string){
	m.fileHash = h;
}
func(m FileMeta)GetRepository() *Repository{
	return m.repository;
}
func(m * FileMeta)SetRepository(r * Repository){
	m.repository = r;
}

func(m FileMeta)GetIncomplete() int{
	return m.incomplete;
}
func(m * FileMeta)SetIncomplete(i int){
	m.incomplete = i;
}
func(m FileMeta)GetNoStaging()bool{
	return m.noStaging
}
func(m *FileMeta)SetNoStaging(b bool){
	m.noStaging = b
}

func NewFileMeta(ftype int, path string, from int64, size int64, hash string) *FileMeta {
	fileMeta := new(FileMeta)
	fileMeta.T = ftype
	fileMeta.P = path
	fileMeta.F = from
	fileMeta.S = size
	fileMeta.fileHash = hash
	return fileMeta
}

func StringToFileMeta(content string) *FileMeta {
	meta := FileMeta{}
	if err := json.Unmarshal([]byte(content), &meta); err == nil {
		return &meta
	}else{
		return nil;
	}
}
func BytesToFileMeta(content []byte) *FileMeta {
	meta := FileMeta{}
	if err := json.Unmarshal(content, &meta); err == nil {
		return &meta
	}else{
		return nil;
	}
}

func FileMetaToString(fileMeta *FileMeta) string {
	bytes, _ := json.Marshal(fileMeta)
	return string(bytes)
}

type CloudPath struct{
	Compressed bool
	Encrypted  bool
	State      byte
	Path       string
	RemoteName string
	FileName string
	Bucket  string
	Hash       string
	FileID     string
}


//@path "1001:AnySync1/b330d3d11aa4447649020adbd389ea6ed5a9b751299c859e08106fcb/objects/35/ea/2d/79bcf5c0734edb77a4358834ed68d73281ee81b26356347717.obj@ef2288c819c3d12a5009f9a85e1a232d033b9be0#4_zee48aadaf1be739e60250918_f108842cf70647ab7_d20191228_m010713_c000_v0001063_t0049"
//@return encrypted, compressed, normal, remoteName, cloudPath (CloudPath is "SHA1#FileID" )
func DecodePath(path string) * CloudPath{
	//ret := make(map[string]string)
	cp := new(CloudPath)
	c := path[0]
	cp.Encrypted = c=='1'
	c = path[1]
	cp.Compressed = c == '1';
	c = path[2]
	cp.State = c;// utils.ToInt(c)
	//normal := c == '0';
	pos := strings.Index(path, ":")
	cp.RemoteName = path[3:pos]
	cloudPath := path[pos+1:]
	if(cp.RemoteName == LoadAppParams().GetSelectedRemoteName()){
		pos := strings.Index(cloudPath, META_PATH_ID_SEPARATOR)
		var text string
		if  pos > 0 {
			text = cloudPath[pos+1:]
			cloudPath = cloudPath[0:pos]
			if pos = strings.Index(text, META_PATH_HASH_SEPARATOR); pos > 0 {
				cp.Hash = text[0:pos]
				cp.FileID = text[pos+1:]
			}else{
				cp.Hash = text;
			}
		}
		pos2 := strings.Index(cloudPath, "/")
		cp.FileName = cloudPath[pos2 + 1:]
		pos3 := strings.Index(cloudPath, ":")
		cp.Bucket = cloudPath[pos3+1:pos2]
	}
	cp.Path = cloudPath;
	return cp;
	//return encrypted, compressed, normal, remoteName, cloudPath;
}

func NewActionResponseWithError(code AsErrorCode)*ActionResponse{
	res := new(ActionResponse)
	res.ErrorCode = uint32(code);
	return res;
}

func IsVersionOk(version string)bool{
	if(len(version) == 0){
		return false;
	}
	return true;
}

func UpdateFileID(fileMeta *FileMeta, fileID string) {
	//fileMeta.P: 1001:AnySync1/95f76264975ff3ffa473fa705022d87d4238cfe3797aaf652730e420/objects/d1/e8/f4/1ad8e208eda8ac97ce36c94d9fdafd69f01427940427fcb954.obj@da6259bbe98a781b7a317871410264680447b1aa#4_zee48aadaf1be739e60250918_f11478e65574d0f7c_d20180412_m161836_c000_v0001050_t0025
	pos := strings.Index(fileMeta.P, META_PATH_ID_SEPARATOR)
	fileMeta.P = fileMeta.P[0:pos] + META_PATH_ID_SEPARATOR + fileID
}

func UpdateMeta(userID, fileHash, id string) {
	Debug("updateMeta, user:", userID, "; fileHash:", fileHash, ", ID:", id)
	if fileHash == "" || id == "" {
		return
	}

	fileMeta := GetDatObject(fileHash);
	UpdateFileID(fileMeta, id)
	nc := FileMetaToString(fileMeta)
	UpdateDatFile(fileHash, []byte(nc), userID)
}

func GetFileHash( filename, suffix string) string {
	if FileSize(filename) == 0 {
		return ZERO_HASH
	}
	file, err := os.OpenFile(filename, os.O_RDONLY|syscall.O_NONBLOCK, 0600)
	if err != nil {
		return ""
	}
	defer file.Close()
	hash := NewHash();// NewHashWithHeader([]byte(repoHash))
	io.Copy(hash, file)
	var result []byte;
	if(suffix == ""){
		suffix = GetHashSuffix();
	}
	result = SumSuffix(hash, suffix);// SumWithTail(hash, []byte(repoHash))
	//Debug("GetFileHash,file: ", filename,  ", suffix: ", suffix, ", result: ", fmt.Sprintf("%x", result))
	return fmt.Sprintf("%x", result)
}

/**
 * Get Hash for a file path. Local's path is changed to lower case first.
 * With the help of filepath.Clean, we can get canonical form of a file path.
 * So "root//Documents/" -> "root/Documents"
 * @param relativePath an example: "root/documents/api", where repo name is "documents". It starts with ROOT_NODE declared in Consts.go
 */
func GetFolderPathHash(relativePath string) string {
	if(relativePath == ROOT_NODE){
		return NULL_HASH;
	}
	path := CleanPath(relativePath, true)
	hash := getTextHash(path, GetHashSuffix())
	//	Debug("GetFolderPathHash, path ", path,  ", fileHash suffix: ", string(HASH_SUFFIX_BYTES), "; Hash: " , hash)
	return hash
}

func UpdateConflictFileNameKey(row []byte){
	for i:=0; i< 2 ; i++  {
		row[4 + i] = 0
	}
}

//Calculate file name key. Based on file or folder's name, return the file name key used in bin file.
func CalculateFileNameKey(name string, isDir bool, folderHash string, suffix string) string {
	//Debug("GetFileNameHash.HashSuffix: ", suffix, "; name: ", name, "; folderHash:", folderHash)
	if suffix == ""{
		suffix = GetHashSuffix()
	}
	resetFirstTwo := false;
	if isDir {
		name = folderHash + strings.ToLower(name) + "d"
	} else {
		name += "f"
		if strings.HasPrefix(name, CONFLICT_NAME_PREFIX) {
			resetFirstTwo = true;
			name = name[len(CONFLICT_NAME_PREFIX):];
		}
	}
	ret := getTextHash(name, suffix);
	if(resetFirstTwo){
		fileArray := FromHex(ret)
		for i:=0; i< 2 ; i++  {
			fileArray[i] = 0
		}
		ret = hex.EncodeToString(fileArray)
	}
	//Debug("CreateFileNameKey, name:", name , "; isFolder:", isDir , "key:", ret, "; suffix:", suffix)
	return ret;
}

func getTextHash(text , suffix string) string {
	hash := NewHash()
	hash.Write([]byte(text))
	return hex.EncodeToString(SumSuffix(hash, suffix))
}

func GetFullPathHash(relativePath string) []string {
	var list []string
	for {
		if relativePath == ROOT_NODE {
			list = append(list, NULL_HASH)
			break
		}
		hash := GetFolderPathHash(relativePath)
		list = append(list, hash)

		relativePath = filepath.Dir(relativePath)
	}
	//reverse the list, make top directory in the front.
	for i := len(list)/2 - 1; i >= 0; i-- {
		opp := len(list) - 1 - i
		list[i], list[opp] = list[opp], list[i]
	}
	return list
}

func TimeTrack(start time.Time, name string) {
	elapsed := time.Since(start)
	Debug( name, "took", elapsed)
}
