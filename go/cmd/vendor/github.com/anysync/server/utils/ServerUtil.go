// Copyright (c) 2020, Yanbin (Henry) Zheng <ybzheng@gmail.com>
// All rights reserved.
//
// Use of this source code is governed by a AGPLv3 license that can be
// found in the LICENSE file.

package utils

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/burntsushi/toml"
	

	"os"
	"path/filepath"
	"strings"
	"time"
)


/*
'~' can be used in Directory.

If it's root server, DbServer and ServerName must be identical.
DbServer is the root server, which stores user info.
ServerName is the name of server itself.
 */
type ServerConfig struct {
	Directory  string
	KeyFile    string
	CertFile   string
	DbServer   string //database server
	Auth       string
	LinkedServers    string   //linked servers, separated by ,
	Hosts string //map of domain name to ip, like /etc/hosts. format:  domainName:InternalIP-ExternalIP e.g.  a1.anysync.net:10.1.31.1-45.63.11.117", a2.anysync.net:10.2.31.1-5.63.11.119
	LogLevel    int
}

func getDefaultServerConfig() *ServerConfig {
	var defaultServerConfig = ServerConfig{
		Directory:  "",
		KeyFile:    "server.key",
		CertFile:   "server.crt",
	}
	return &defaultServerConfig
}

func SaveServerConfigFile(config *ServerConfig, file string) {
	buf := new(bytes.Buffer)
	if err := toml.NewEncoder(buf).Encode(config); err != nil {
		return
	}
	WriteString(file, buf.String())
}

func GetServerConfigFile()string{
	configDir, _ := GetServerConfigDir()
	if !FileExists(configDir) {
		MkdirAll(configDir)
	}
	configFile := filepath.Join(configDir, "server.conf")
	return configFile;
}

func LoadServerConfigFile(configFile string) (*ServerConfig, error) {
	if _, err := os.Stat(configFile); os.IsNotExist(err) {
		return nil, errors.New("config file does not exist")
	} else if err != nil {
		return nil, err
	}

	conf := getDefaultServerConfig()
	if _, err := toml.DecodeFile(configFile, conf); err != nil {
		Debug("Config file cannot be decoded: ", configFile)
		return nil, err
	}
	if strings.Index(conf.Directory, "~") >= 0{
		conf.Directory = ExpandTilde(conf.Directory)
	}

	return conf, nil
}

var gServerConfig *ServerConfig

func LoadServerConfig() *ServerConfig {
	if gServerConfig != nil {
		return gServerConfig
	}
	configFile := GetServerConfigFile()
	fmt.Printf("ServerConfig file is %s\n", configFile)
	if !FileExists(configFile) {
		SaveServerConfigFile(getDefaultServerConfig(), configFile)
	}
	config, err := LoadServerConfigFile(configFile)
	if err != nil {
		fmt.Println("Error is", err)
		return nil
	}
	gServerConfig = config
	SetLogLevel(config.LogLevel)

	root := config.Directory
	if IsWindows() {
		root =  filepath.Join(os.Getenv("ALLUSERSPROFILE"),"AnySync") + "\\"
	} else {
		if !strings.HasSuffix(root, "/") {
			root += "/"
		}
	}
	Debugf("Set ServerRoot:%s\n", root)
	ServerRoot = root;

	return config
}

func (config  ServerConfig) IsLinkedServer(server string)bool{
	if strings.Index(config.LinkedServers, server) >= 0 {
		return true
	}else{
		return false
	}
}
func (config ServerConfig)GetIP(server string)string{
	if config.Hosts == ""{
		return ""
	}
	tokens := strings.Split(config.Hosts, ",")
	for _, token := range tokens {
		pos := strings.Index(token, "-")
		if pos < 0 {
			continue
		}
		name := strings.TrimSpace(token[0:pos])
		if strings.Index(name, server) >= 0 {
			return strings.TrimSpace(token[pos+1:])
		}
	}
	return ""
}

func (config ServerConfig)GetInternalIP(server string)string{
	if config.Hosts == ""{
		return ""
	}
	tokens := strings.Split(config.Hosts, ",")
	for _, token := range tokens {
		pos := strings.Index(token, ":")
		if pos < 0 {
			continue
		}
		name := strings.TrimSpace(token[0:pos])
		if strings.Index(name, server) >= 0 {
			text := strings.TrimSpace(token[pos+1:])
			pos = strings.Index(text, "-")
			if pos > 0 {
				text = text[0:pos]
			}
			return text;
		}
	}
	return ""
}

func GetTmpOnServer() string {
	return GetRootOnServer() + "/tmp/"
}

func GetTaskRootOnServer() string {
	root := GetRootOnServer()
	return root + "/tasks"
}
func GetUserTaskRootOnServer(user string) string {
	root := GetRootOnServer()
	now := time.Now().Unix()
	if user == "1" { //test account
		return fmt.Sprintf("%s/tasks/0/0/1/%d_1", root, now)
	} else {
		return fmt.Sprintf("%s/tasks/%s/%d_1", root, IntStringToPath(user), now) // root + "/tasks/" + IntStringToPath(user) + "/" + deviceID;
	}

}

func GetClientDatOffset(user, deviceID string, shareHash string) (uint32, uint32) {
	serverRepo := GetUserRootOnServer(user)
	var clientsData string
	if shareHash != "" {
		clientsData = serverRepo + "share/" + HashToPath(shareHash) + "/" + CLIENTS_DAT_FILE //"clients.dat"
	} else {
		clientsData = serverRepo + "data/" + CLIENTS_DAT_FILE //"clients.dat"
	}
	data, _ := LoadFile(clientsData, UTF8)
	syncData := data.GetString("sync."+deviceID, "")
	sizeText := data.GetString("size", "0")
	var offset uint32
	size := ToUint32(sizeText)
	if syncData != "" {
		tokens := strings.Split(syncData, ",")
		//if tokens[0] == myID {
		offset = ToUint32(tokens[1])
	}
	Debug("GetClientDatOffset returns:", offset, "; fileSize:", size, "; dat file:", clientsData)
	return uint32(offset), size
}

func CreateZipForUser(user string, includeAll bool) string {
	//server := GetRootOnServer()
	root := GetUserRootOnServer(user)
	var folders []string
	if includeAll {
		folders = []string{
			//the paths below cannot contain double slash "//", otherwise it will cause problem
			//root + "objects",
			root + "tree",
			root + "data/server.bin",
			root + "names",
		}
	} else {
		folders = []string{
			root + "data/server.bin",
		}
	}
	//transformMap := map[string]string{
	//	//"objects": "objects",
	//	//"tree": "tree",
	//	user: "names",
	//};
	tmpDir := GetRootOnServer() + "/tmp/"
	if !FileExists(tmpDir) {
		MkdirAll(tmpDir)
	}
	zipFileName := GenerateRandomHash() + ".tlz"
	CreateZip(folders, nil, nil, tmpDir+zipFileName)
	return zipFileName
}





