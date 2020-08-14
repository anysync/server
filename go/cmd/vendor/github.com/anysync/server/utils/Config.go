// Copyright (c) 2020, Yanbin (Henry) Zheng <ybzheng@gmail.com>
// All rights reserved.
//
// Use of this source code is governed by a AGPLv3 license that can be
// found in the LICENSE file.

package utils

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/burntsushi/toml"
	"github.com/golang/protobuf/proto"
	"github.com/mitchellh/go-homedir"
	"io/ioutil"
	"log"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

const(
	configDirName = ".AnySync"
	OFFSET_FILE = "offset.dat"
	REMOTES_FILE = "remotes.conf"

	//Track local changes and sync
	CONFIG_MODE_BIDIRECTION = 0
	//Placeholder, no local directory so do not track local changes.
	CONFIG_MODE_PLACEHOLDER = 1
	//Placeholder, with local directory,  do not track local deletes and modifies, but track new files.
	CONFIG_MODE_NEW_ONLY    = 2



	//LibreOffice creates files like .~lock.filename.ext#
	//can handle file path such as */caches/*...
	DEFAULT_EXCLUDED = "~$*, ~*.tmp, .DS_Store, *.part, *.crdownload, *~, .*.swp, .Spotlight-V100, .Trashes, ._*, *_, desktop.ini, ehthumbs.db, Thumbs.db, .dropbox, .dropbox.attr, .~lock.*, *.sqlite, *.sqlite-*, *.sqlite.lock, *.kgdb, *.kgdb-*, */$RECYCLE.BIN/*, */caches/*"

	LOG_LEVEL_CRITICAL = 4 //fs.LogLevelCritical
	LOG_LEVEL_ERROR = 3 //fs.LogLevelError;
	LOG_LEVEL_WARN = 2 //fs.LogLevelError;
	LOG_LEVEL_INFO = 1 //fs.LogLevelInfo;
	LOG_LEVEL_DEBUG = 0 //fs.LogLevelDebug;
)

type Proxy struct{
	ProxyType int;
	Host string;
	Port int;
	Username string;
	Password string;
}

type AppParams struct{
	Server string; //only used to set the initial value of Config.ServerAddress
	//IsOfficial bool;
	TlsEnabled bool;
	TlsSkipVerify bool;
	RemoteNameCode string;
	AllowedRemotes string; //remote name codes separated by ','. Used only on server side.
	Storage  []*RemoteStorage;
	storageMap map[string]  *RemoteStorage;
	allowedMap map[string] *RemoteStorage;
	file  string;
}

type Config struct {
	User          string;
	Email         string;
	DeviceID      string; //device id
	ServerAddress string;
	ServerIp    string; //it's used to overwrite ServerAddress
	ServerPort    int;
	GoogleDriveClientID string;
	GoogleDriveClientSecret string;
	DropboxClientID string;
	DropboxClientSecret string;
	TlsEnabled    bool;
	PackMinSize   int;
	RateLimit     int; //in kbps
	Mode          int; //0:bidirection ; 1: upload only; 2: download only ; 3: Ignore deletion?
	ThreadCount   int;
	Excluded      string;
	Included      string;
	MaxSize       int64;
	//MinSize       int64;
	MaxAge        int64;
	MinAge        int64;
	Proxy         Proxy;
	LogLevel      int; //0:debug; 1:info; 2:warning; 3:error; 4:critical
	Locals          string;
	ScanInterval    int; //in minutes
	//Repository    []Repository;
}

type RemoteStorage struct{
	Type string;
	EndPoint string;
	Key string;
	Bucket string;
	Secret string;
	Region string;
	RemoteNameCode string;
}

func (this Proxy) Equals(p Proxy)bool{
	if(this.ProxyType == p.ProxyType && this.Host == p.Host && this.Port == p.Port && this.Username == p.Username && this.Password == p.Password){
		return true;
	}
	return false;
}

func  GetRepositoryLocal(name, folderHash string)string{
	if(folderHash != "") {
		shareFolder := GetFirstShareFolderOnClient(folderHash)
		if (shareFolder != nil && !IsShareFolderOwner(shareFolder)) {
			return GetTopShareFolder() + HashToPath(shareFolder.Hash) + "/" ;
		}
	}

	repos := GetRepositoryList();
	for _, r := range repos{
		if(r.Name == name){
			return r.Local;
		}
	}
	return "";
}

func (c Config) GetLocalPath(index int) string{
	if len(c.Locals) == 0 {
		return "";
	}
	locals := strings.Split( c.Locals,  LOCALS_SEPARATOR1);
	for _, local := range locals{
		Debug("Local:", local)
		pos := strings.Index(local, LOCALS_SEPARATOR2);
		if pos <= 0 {
			if len(locals) == 1 {
				return strings.TrimSpace(local)
			}
			continue
		}
		first := local[0:pos]
		if(ToInt(strings.TrimSpace(first)) == index){
			return strings.TrimSpace(local[pos + 1:])
		}
	}
	return "";
}

/**
@return nil if error (remotes data cannot be decrypted) occurs.
 */
func GetRepositoryMap()map[string]*Repository {
	return GetRepositoryMapBy(false)
}

func GetRepositoryMapBy(useRepoHash bool)map[string]*Repository {
	ret := make(map[string]*Repository)

	base := GetTopTreeFolder() + HashToPath(NULL_HASH)
	binFile := base + ".bin";
	if(!FileExists(binFile)){
		return ret;
	}
	rows := ReadBinAll(binFile, false)
	if(len(rows)  == 0){
		return ret;
	}
	for i, row := range rows{
		if(i==0){
			continue;
		}
		key := CreateXattribKey(NULL_HASH, uint32(i) );
		xa, found := DbGetStringValue(key,false);
		if(found){
			fattr := FileAttribs{};
			fattr.Attribs = make(map[string][]byte);
			if(proto.Unmarshal([]byte(xa), &fattr) == nil){
				bs := fattr.Attribs[ATTR_REPO]
				repo := DecryptRepository(bs);
				if repo == nil {
					return nil;
				}
				//repo.Name = name;
				repo.Hash = row.ToHashString();
				if(useRepoHash){
					ret [repo.Hash] = repo;
				}else {
					ret [repo.Name] = repo;
				}
			}
		}
	}
	return ret;
}

func UpdateRepository(repo * Repository)bool{
	key := CreateXattribKey(NULL_HASH, repo.Index );
	fattr := FileAttribs{};
	fattr.Attribs = make(map[string][]byte);
	fattr.Attribs[ATTR_REPO] = GetRepositoryInBytes(repo)

	if bs, err := proto.Marshal(&fattr); err == nil {
		DbSetValue(key, bs);
	}else{
		return false;
	}
	return true
}

func GetRepositoryList()[]*Repository {
	return GetAllRepositoryList(true);
}

func GetAllRepositoryList(includeShare bool)[]*Repository {
	var ret []*Repository;

	base := GetTopTreeFolder() + HashToPath(NULL_HASH)
	binFile := base + ".bin";
	if(!FileExists(binFile)){
		Debug("NULL_HASH bin file does not exist")
		return ret;
	}
	rows := ReadBinAll(binFile,false)
	if(len(rows)  == 0){
		Debug("NULL_HASH bin file contains no row.")
		return ret;
	}
	for i, row := range rows{
		if(i==0){
			continue;
		}
		if(!includeShare && row.ToHashString() == SHARED_HASH){
			continue
		}
		key := CreateXattribKey(NULL_HASH, uint32(row.Index) );
		xa, found := DbGetStringValue(key, false);
		if(found){
			fattr := FileAttribs{};
			fattr.Attribs = make(map[string][]byte);
			if(proto.Unmarshal([]byte(xa), &fattr) == nil){
				bs := fattr.Attribs[ATTR_REPO]
				repo := DecryptRepository(bs);
				if(repo == nil){
					Error("repo cannot be decrypted. bytes.length: ", len(bs), "; binFile: ", binFile)
					return nil;
				}
				repo.Hash = row.ToHashString();
				repo.Index = uint32(i);
				config := LoadConfig();
				if repo.Hash != SHARED_HASH {
					local := config.GetLocalPath(i);
					Debug("For i:", i, "; localPath:", local)
					if (len(local) > 0) {
						repo.Local = local;
					}
				}
				Debug("i:", i, ". --- repo.Local: ", repo.Local)
				ret = append(ret, repo);
			}
		}
	}
	return ret;
}

func GetShareFolderList(repos []*Repository)[]*Repository {
	var ret []*Repository;

	base := GetTopTreeFolder() + HashToPath(SHARED_HASH)
	binFile := base + ".bin";
	if(!FileExists(binFile)){
		return ret;
	}
	rows := ReadBinAll(binFile,false)
	if(len(rows)  == 0){
		return ret;
	}
	config := LoadConfig();
	for i, row := range rows{
		if(i==0 || IsFileModeDeleted(row.FileMode) ){
			continue;
		}

		key := CreateXattribKey(SHARED_HASH, uint32(row.Index) );
		xa, found := DbGetStringValue(key, false);
		if(found){
			fattr := FileAttribs{};
			fattr.Attribs = make(map[string][]byte);
			if(proto.Unmarshal([]byte(xa), &fattr) == nil){
				if shareFolder := GetShareFromBytes(fattr.Attribs[ATTR_SHARE]); shareFolder != nil {
					repo := Repository{};
					repo.Name = shareFolder.Name
					repo.Hash = shareFolder.Hash;
					repo.Index = uint32(i);
					repo.EncryptionLevel = shareFolder.EncryptionLevel;
					repo.Includes = shareFolder.Includes;
					repo.Owner = shareFolder.Owner;
					repo.ShareID = shareFolder.ID;
					repo.HashSuffix = shareFolder.HashSuffix
					if(shareFolder.Owner != "" && shareFolder.Owner != config.User) {
						repo.Local = GetTopShareFolder() + HashToPath(shareFolder.Hash) + "/"
						repo.ShareState = REPO_SHARE_STATE_SHARE
						for _, r := range repos{
							if(len(r.Remote) > 0 && (r.Remote[0].Name == REMOTE_TYPE_SERVER_NAME || r.Remote[0].Name == LoadAppParams().GetSelectedRemoteName())){
								repo.Remote = r.Remote;
								break
							}
						}
					}else{
						binFile := GetTopTreeFolder() + HashToPath(shareFolder.Hash) + EXT_BIN
						row := GetRowAt(binFile, 0)
						repoHash  := GetRepoHash(row.Raw)
						for _, r := range repos{
							if(r.Hash == repoHash){
								repo.Local = GetFolderFullPath(shareFolder.Hash)
								repo.ShareState = REPO_SHARE_STATE_OWNER
								repo.Remote = r.Remote;
								break
							}
						}
					}
					ret = append(ret, &repo);
				}
			}
		}
	}
	return ret;
}

func GetFirstShareFolderOnClient(folderHash string) *ShareFolder {
	binFile := GetTopTreeFolder() + "/" + HashToPath(SHARED_HASH) + EXT_BIN;
	rows := ReadBinAll(binFile,false)
	if(len(rows)  == 0){
		Debug("rows.size is 0")
		return nil;
	}
	var shareFolder *ShareFolder;
	for i, row := range rows{
		if(i==0 || IsFileModeDeleted(row.FileMode) ){
			continue;
		}
		key := CreateXattribKey(SHARED_HASH, uint32(i) );
		xa, found := DbGetValue(key);
		if(found){
			fattr := FileAttribs{};
			fattr.Attribs = make(map[string][]byte);
			if(proto.Unmarshal([]byte(xa), &fattr) == nil){
				if s := GetShareFromBytes(fattr.Attribs[ATTR_SHARE]); s != nil {
					if(s.Hash == folderHash){
						if(shareFolder == nil){
							shareFolder = s;
						}else{
							MapAddAll1(shareFolder.MemberKeys, s.MemberKeys)
						}
					}
				}
			}else{
				Debug("Unmarshall return nil: ", hex.EncodeToString([]byte(xa)))
			}
		}else{
			Debug("key not found: ", key)
		}
	}
	return shareFolder;
}

func GetShareFoldersOnClient(folderHash string) []*ShareFolder {
	binFile := GetTopTreeFolder() + "/" + HashToPath(SHARED_HASH) + EXT_BIN;
	rows := ReadBinAll(binFile,false)
	if(len(rows)  == 0){
		Debug("rows.size is 0")
		return nil;
	}
	var shareFolders  []*ShareFolder;
	for i, row := range rows{
		if(i==0 || IsFileModeDeleted(row.FileMode) ){
			continue;
		}
		key := CreateXattribKey(SHARED_HASH, uint32(i) );
		xa, found := DbGetValue(key);
		if(found){
			fattr := FileAttribs{};
			fattr.Attribs = make(map[string][]byte);
			if(proto.Unmarshal([]byte(xa), &fattr) == nil){
				if s := GetShareFromBytes(fattr.Attribs[ATTR_SHARE]); s != nil {
					if(s.Hash == folderHash){
						shareFolders = append(shareFolders, s)
					}
				}
			}else{
				Debug("Unmarshall return nil: ", hex.EncodeToString([]byte(xa)))
			}
		}
	}
	return shareFolders;
}

func IsShareFolderOwner(folder *ShareFolder)bool{
	if(folder == nil){
		return true;
	}
	config := LoadConfig();
	if(folder.Owner == config.User){
		return true;
	}else{
		return false;
	}
}
func (config Config) GetDevice() uint32{
	return uint32(ToInt(config.DeviceID))
}

func(config Config) GetServer()string{
	return fmt.Sprintf("%s:%d", config.ServerAddress, config.ServerPort);// "192.168.1.222"
}

func(config Config)GetUrlPrefix() string{
	var p string;
	if(config.TlsEnabled){
		p = "https"
	}else{
		p = "http"
	}
	return fmt.Sprintf("%s://%s:%d", p, config.ServerAddress, config.ServerPort);// "192.168.1.222"
}

func getDefaultConfig() *Config{
	l := LOG_LEVEL_INFO
	if DEBUG {
		l = LOG_LEVEL_DEBUG
	}
	p := LoadAppParams()
	var defaultConfig = Config{
		User:     "1",
		DeviceID: "1",
		ServerPort:    SERVER_MAIN_PORT,
		PackMinSize:   PACK_FILE_SIZE_MIN_THRESHOLD,
		ServerAddress: p.Server,
		TlsEnabled:    p.TlsEnabled,
		ScanInterval:    10,
		RateLimit:     0,
		ThreadCount:   8,
		Excluded:      DEFAULT_EXCLUDED,
		LogLevel:      l,

	}
	return & defaultConfig
}

var CurrentHost string;
func (conf * Config) IsOfficialSite() bool {
	if strings.Index(strings.ToLower(conf.ServerAddress), "anysync.net") >= 0 { //only verify certificate when connecting to official server
		return true
	} else {
		return false
	}

}

func LoadConfigFile(configFile string) (*Config, error) {
	if _, err := os.Stat(configFile); os.IsNotExist(err) {
		return nil, errors.New("Config file does not exist.")
	} else if err != nil {
		return nil, err
	}

	conf := getDefaultConfig();//DefaultConfig
	if _, err := toml.DecodeFile(configFile, conf); err != nil {
		log.Println("Load config err: ", err)
		return nil, err
	}

	return conf, nil
}

func GetServerConfigDir() (string, error) {
	if(IS_MAIN_SERVER_SIDE && IsWindows()) {
		return filepath.Join(os.Getenv("ALLUSERSPROFILE") , "AnySync"), nil
	}
	var configDirLocation string

	homeDir, err := homedir.Dir()
	if err != nil {
		return "", err
	}

	configDirLocation = filepath.Join(homeDir, configDirName)
	return configDirLocation, nil
}

func SaveConfigFile(conf  * Config, file string)bool{
	config := CloneObject(*conf).(Config);//new ( Config );
	buf := new(bytes.Buffer)
	if err := toml.NewEncoder(buf).Encode(config); err != nil {
		return true;
	}
	oldConfig, _ := LoadConfigFile(file);
	WriteString(file, buf.String())
	skip := false;
	if(oldConfig == nil){skip = true;}
	if(oldConfig != nil && oldConfig.Proxy.Equals(config.Proxy)){
		skip = true;
	}
	if(!skip) {
		config.UpdateProxy()
	}
	if(oldConfig != nil && oldConfig.ThreadCount == config.ThreadCount){
		skip = true;
	}

	skip = false;
	if(oldConfig != nil && oldConfig.RateLimit == config.RateLimit){
		skip = true;
	}
	return skip;
}

var CurrentConfig * Config;
var CurrentRepoMap map[string]string;

func ReloadConfig() *Config{
	CurrentConfig = nil;
	return LoadConfig();
}
func LoadConfig() *Config {
	if(CurrentConfig != nil){
		return CurrentConfig
	}

	configDir := GetAppHome();
	if(configDir == ""){
		CurrentConfig = getDefaultConfig();
		return CurrentConfig;
	}
	if(!FileExists(configDir)){
		MkdirAll(configDir)
	}
	configFile := filepath.Join(configDir, "config");
	if(!FileExists(configFile)){
		CurrentConfig = getDefaultConfig();
	}else {
		conf, _ := LoadConfigFile(configFile);
		CurrentConfig = conf
	}
	SetLogLevel(CurrentConfig.LogLevel)

	return CurrentConfig;
}

var CurrentParams * AppParams;

func LoadAppParams() * AppParams{
	if CurrentParams != nil {
		return CurrentParams
	}
	usr, err := user.Current()
	if err != nil {
		Critical(err)
	}
	paramsDir := usr.HomeDir + "/.AnySync"
	if(!FileExists(paramsDir)){
		MkdirAll(paramsDir)
	}
	rcFile := "anysync.rc";
	if IS_MAIN_SERVER_SIDE {
		rcFile = "server.rc"
	}
	var paramsFile string;
	if(IS_MAIN_SERVER_SIDE && IsWindows()) {
		paramsFile = filepath.Join(os.Getenv("ALLUSERSPROFILE"),"AnySync", rcFile)
	}else {
		paramsFile = filepath.Join(paramsDir, rcFile);
	}
	if !FileExists(paramsFile) {
		dir, err := filepath.Abs(filepath.Dir(os.Args[0]))
		if err != nil {
			log.Fatal(err)
		}
		original := dir + "/" + rcFile
		Info("original rc file:", original)
		CopyFile(original, paramsFile);
	}
	CurrentParams = & AppParams{};
	if _, err := toml.DecodeFile(paramsFile, CurrentParams); err != nil {
		log.Fatal("Cannot find app params file")
		return nil
	}

	CurrentParams.storageMap = make(map[string]  *RemoteStorage)
	CurrentParams.allowedMap = make (map[string]  *RemoteStorage)

	for _,r := range CurrentParams.Storage {
		if r.Secret == "" {
			r.Secret = os.Getenv("S3CODE" + r.RemoteNameCode)
		}
		CurrentParams.storageMap[r.RemoteNameCode] = r
	}

	if(len(CurrentParams.AllowedRemotes) > 0){
		tokens := strings.Split(CurrentParams.AllowedRemotes, ",")
		for _, t := range tokens {
			t = strings.TrimSpace(t)
			if s, ok := CurrentParams.storageMap[t] ; ok {
				CurrentParams.allowedMap[t] = s
			}
		}
	}
	CurrentParams.file = paramsFile
	return CurrentParams;
}

func(p * AppParams)Save()error{
	paramsFile := p.file

	buf := new(bytes.Buffer)
	if err := toml.NewEncoder(buf).Encode(p); err != nil {
		return err;
	}
	return WriteString(paramsFile, buf.String())
}


func (p * AppParams) IsRemoteNameCodeAllowed(code string) bool{
	if len(code) == 0 {
		return false
	}
	if _, ok := p.allowedMap[code] ; ok{
		return true
	}else{
		return false
	}
}

func (p * AppParams) GetSelectedStorage() * RemoteStorage{
	return p.storageMap[p.RemoteNameCode];
}

func (p * AppParams) GetSelectedRemoteName() string{
	s := p.GetSelectedStorage()
	if(s != nil){
		return s.RemoteNameCode
	}else{
		return "0"
	}
}

func (p * AppParams) GetStorage(name string) * RemoteStorage{
	return p.storageMap[name]
}

func (p * AppParams) GetStorageBucket(name string) string{
	s := p.GetStorage(name);
	if(s != nil){
		return s.Bucket
	}else {
		return "";
	}
}

func GetConfigFile()string{
	return GetAppHome() + "config";
}

func GetRemotesIncludingTemps() * Repository {
	r1 := GetRemotes();
	r2 := GetTempRemotes();
	for _, r := range r2.Remote {
		found := false;
		for _, e := range r1.Remote {
			if(e.Name == r.Name){
				found = true;
				break;
			}
		}
		if(!found) {
			r1.Remote = append(r1.Remote, r)
		}
	}
	return &r1;
}

func GetRemotes() Repository {
	ret := Repository{};

	repos := GetRepositoryList();
	for _, r := range repos{
		for _, remote :=range r.Remote {
			found := false;
			for _, existing := range ret.Remote {
				if(existing.Name == remote.Name){
					found = true;
					break;
				}
			}
			if(!found){
				ret.Remote = append(ret.Remote, remote);
			}
		}
	}
	return ret;
}

var remotesLock = &sync.Mutex{}
func GetTempRemotes() Repository{
	remotesLock.Lock()
	defer remotesLock.Unlock()
	Debug("Entered GetRemotes")
	dir := GetAppHome();
	fileName := dir + "data/" + REMOTES_FILE;
	//fmt.Println("Remote FileHash is ", fileName)
	fattr := Repository{};

	if(!FileExists(fileName)){
		//fmt.Println("Remote file does not exist.")
		return fattr;
	}
	Debug("To call GetClientMasterEncKey")
	key, err := GetClientMasterEncKey();
	if(err != nil){
		fmt.Println("Failed to get master key")
		return fattr
	};
	if bs, err := ioutil.ReadFile(fileName); err == nil {
		if bs, err = Decrypt(bs, &key); err == nil {

			if (proto.Unmarshal(bs, &fattr) == nil) {
				return fattr;
			}else{
				fmt.Println("Failed to unmarshall remotes.conf")
			}
		}else{
			fmt.Println("Failed to decrypt remotes.conf")
		}
	}
	return fattr;
}

func SaveTempRemotes(remotes * Repository) error{
	remotesLock.Lock()
	defer remotesLock.Unlock()
	Debug("To save remotes...")
	bs, err := proto.Marshal(remotes);
	if(err != nil){return err};
	dir  := GetAppHome();
	fileName := dir + "/data/" + REMOTES_FILE;
	if bs, err = EncryptUsingMasterKey(bs); bs != nil {
		if err = WriteBytesSafe(fileName, bs); err == nil {
			//return SendData("remotes", "remotes", string(bs), nil)
			return nil;
		}
	}
	Debug("Error is ", err)
	return err;
}

func DecryptRepository(bs [] byte) *Repository {
	if data, err := DecryptUsingMasterKey(bs, nil); err != nil {
		return nil
	}else{
		r := Repository{};
		if(proto.Unmarshal(data, &r) == nil) {
			return &r;
		}
	}
	return nil;
}

func GetRepositoryInBytes(repo * Repository)[]byte{
	//repo := GetRemotes();
	bs, err := proto.Marshal(repo);
	if(err != nil){return nil};
	if bs, err = EncryptUsingMasterKey(bs); bs != nil {
		return bs;
	}
	Debug("Error is ", err)
	return nil;
}
func GetShareInBytes(repo *ShareFolder)[]byte{
	bs, err := proto.Marshal(repo);
	if(err != nil){
		Warn("GetShareInBytes. Error:", err)
		return nil
	};
	return bs;
}
func GetShareFromBytes(bs []byte) *ShareFolder {
	r := ShareFolder{}
	if proto.Unmarshal(bs, &r) == nil {
		return &r;
	}
	return nil
}

func SaveNewRemote(remotes * Repository, name, remoteType, val string, otherData map[string]string) *Repository {
	if(remotes == nil ){
		remotes = GetRemotesIncludingTemps();
	}
	Debug("Enter save new remote. name: ", name, "; type: ", remoteType, "; val: ", val, "; data: ", otherData)
	for _, r := range remotes.Remote {
		if r.Name == name {
			return remotes;
		}
	}
	p := RemoteObject{};
	p.Type = remoteType;
	p.Name = name;
	p.Value = val;
	p.Data = otherData;
	remotes.Remote = append(remotes.Remote, &p);
	SaveTempRemotes(remotes)
	Debug("SaveNewRemote. Remote are ", remotes.Remote)
	CurrentConfig = nil;
	LoadConfig();
	return remotes
}

func CreateNewRemote(remotes * Repository, name, remoteType, val string, otherData map[string]string) *RemoteObject {
	Debug("Enter CreateNewRemote. name: ", name, "; type: ", remoteType, "; val: ", val, "; data: ", otherData)
	for _, r := range remotes.Remote {
		if r.Name == name {
			return r;
		}
	}
	p := RemoteObject{};
	p.Type = remoteType;
	p.Name = name;
	p.Value = val;
	p.Data = otherData;
	return &p;
}

func(this Proxy) ToString()string{
	return fmt.Sprintf("%d|%s|%d|%s|%s", this.ProxyType, this.Host, this.Port, this.Username, this.Password);
}

func(this * Proxy) FromString(text string){
	tokens := strings.Split(text, "|")
	this.ProxyType, _ = strconv.Atoi(tokens[0]);
	this.Host = tokens[1];
	this.Port, _ = strconv.Atoi(tokens[2]);
	this.Username = tokens[3];
	this.Password = tokens[4];
}

func (config Config) UpdateProxy(){
	Debug("Update proxy: ", config.Proxy)
	if(config.Proxy.ProxyType == 0){
		//os.Setenv("HTTP_PROXY", "")
		os.Unsetenv("HTTP_PROXY")

	}else if(len(config.Proxy.Host) > 0 ){
		//os.Setenv("HTTP_PROXY", "http://proxyIp:proxyPort");       http://user:password@host:port/
		if(config.Proxy.Username != "" && config.Proxy.Password != ""){
			os.Setenv("HTTP_PROXY", fmt.Sprintf("http://%s:%s@%s:%d", config.Proxy.Username, config.Proxy.Password, config.Proxy.Host, config.Proxy.Port));
		}else {
			os.Setenv("HTTP_PROXY", fmt.Sprintf("http://%s:%d", config.Proxy.Host, config.Proxy.Port));
		}
	}
}

func CreateConfigFile(fileName string,   email, userID string, deviceID uint32, server string, port int){
	config := getDefaultConfig();
	config.Email = email;
	config.User = userID;
	config.DeviceID = fmt.Sprintf("%d", deviceID);
	config.ServerAddress = server;
	config.ServerPort = port;

	SaveConfigFile(config, fileName)
}
var configUpdateLock = &sync.Mutex{}

func InitRepoMap(){
	CurrentRepoMap = make(map[string]string)
	reposMap := GetRepositoryMap();
	for _, r := range reposMap {
		CurrentRepoMap[r.Hash] = r.Name;
	}
}

func GetGoolgeDriveClientID() string {
	config := LoadConfig();
	return strings.TrimSpace(config.GoogleDriveClientID);
}

func GetGoolgeDriveClientSecret() string{
	config := LoadConfig();
	return strings.TrimSpace(config.GoogleDriveClientSecret);
}

func GetDropboxClientID() string {
	config := LoadConfig();
	return strings.TrimSpace(config.DropboxClientID);
}

func GetDropboxClientSecret() string{
	config := LoadConfig();
	return strings.TrimSpace(config.DropboxClientSecret);
}

