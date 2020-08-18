// Copyright (c) 2020, Yanbin (Henry) Zheng <ybzheng@gmail.com>
// All rights reserved.
//
// Use of this source code is governed by a AGPLv3 license that can be
// found in the LICENSE file.
package client

import (
	"encoding/json"
	"fmt"
	"google.golang.org/grpc"
	"html/template"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/user"
	"path"
	"strconv"
	"strings"
	"time"
	utils "github.com/anysync/server/utils"
)

func init() {
}
func RestHandler(w http.ResponseWriter, r *http.Request) {
	//utils.Debugf("RestHandler.uri:%s, P:%s \n", r.RequestURI, r.URL.P)
	u, _ := url.Parse(r.RequestURI)
	folder := u.Query().Get("d")
	command := utils.GetLastUrlPathComponent(r.URL.Path)
	var ret string
	//utils.Debug("RestHandler.Command: ", command  + " ; req:" + r.RequestURI)
	if command == "restore" {
		utils.Debugf("To call Restore to folder: %s\n", folder)
		//time.Sleep(time.Second * 600)
		if err := Restore(folder); err != nil {
			utils.Error("Couldn't restore files to ", folder)
		}
	} else if command == "rescan" || command == "getupdates" {
		if isScanning() {
			utils.SendToLocal("scanning")
		}else {
			go StartRescan(nil)
		}
		//go RescanFolders([]string{"/Users/IMAC/test"}, true, true)
	} else if command == "restart" {
		utils.Debug("To restart...")
		utils.Restart(false)
	} else if command == "shutdown" {
		os.Exit(0)
	} else if command == "echo" {
	    ret = "OK"
	} else if command == "rescanfolders" {
		utils.Debugf("To call rescan to folders: %s\n", folder)
		if isScanning() {
			utils.SendToLocal("scanning")
		}else {
			go RescanFolders(strings.Split(folder, ","), nil, false, 1, false)
		}
	} else if command == "changes" || command == "renaming" { //CPP client detect changes in folder, it then sends all the changed top folders.
		utils.Debug("changes request")
		bs, _ := ioutil.ReadAll(r.Body)
		utils.Debugf("Request.body: %s", string(bs))
		dirs := strings.Split(string(bs), "|")
		if command == "renaming" {
			go RescanFolders(dirs, nil, false, 1, true)
		} else {
			go RescanFolders(dirs, nil, false, 1, false)
		}
	} else if command == "resetgetall" {
		utils.CallResetGetAll("")
	} else if command == "sharefolder" {
		//if(len(file) > 0){
		//	CallShareFile( u.Query().Get("hash"), u.Query().Get("to"), file);
		//}else {
		CallShareFolder(u.Query().Get("name"), u.Query().Get("hash"), u.Query().Get("to"), u.Query().Get("i"))
	} else if command == "saverepo" {
		SaveRepo(w, r)
	} else if command == "getsettings" {
		ret = getSettings()
	} else if command == "getversions" {
		ret = getVersions(w,r)
	} else if command == "getrepos" {
		ret = getRepos(w, r)
	} else if command == "getrepo" {
		ret = getRepo(w, r)
	} else if command == "getname" {
		ret = getFileNameByKey(w, r)
	} else if command == "getuser" {
		ret = getUserInfo()
	} else if command == "getnames" {
		ret = getFileNamesByKey(w, r)
	} else if command == "getstates" {
		getStates(w, r)
	} else if command == "getsize" {
		ret = getRepoSize(w, r)
	} else if command == "updatesetting" {
		updateSetting(w, r)
	} else if command == "updatelocal" {
		updateConfigLocal(w, r)
	} else if command == "updatepassword" {
		updatePassword(w, r)
	} else if command == "qverify" {
		ret = verifyRepo(w, r, true)
	} else if command == "verify" {
		ret = verifyRepo(w, r, false)
	}else if command == "deleteselected" {
		ret = deleteSelectedFolders(u.Query().Get("fs"));
	}else if command == "restoreselected"{
		ret = restoreSelectedForlders(u.Query().Get("restore"), u.Query().Get("selectedfolders"))
	} else if command == "fix" {
		ret = fixRepo(w, r)
	} else if command == "check" {
		username := u.Query().Get("name")
		user, _ := user.Current()
		name := user.Username;
		pos :=  strings.Index(name, "\\")
		if pos >= 0 {//on windows it's something like "Desktop01\User1"
			name = name[pos+1 :]
		}
		utils.Debug("Received check command. user is ", name, ". In request, user is ", username)
		if strings.ToLower(username) == strings.ToLower(name) {
			ret = "true"
		} else {
			ret = "false"
		}
	} else if command == "register" {
		email := u.Query().Get("e")
		if d, r := ClientRegister("server.anysync.net", 65065, email, "", "ui"); r != nil {
			http.Error(w, r.Error(), 201)
		}else{
			if _, ok := d["registered"]; ok{
				http.Error(w, "", 202)
			}
			ret = "true"
		}
	}else if command == "login" || command == "signup" {
		password := u.Query().Get("p")
		email := u.Query().Get("e")
		name := u.Query().Get("n")
		server := u.Query().Get("s")
		if strings.Index(server, "anysync.net") < 0 {
			params := utils.LoadAppParams()
			if len(server) == 0 {
				server = params.Server // u.Query().Get("s")
			} else {
				params.Server = server;
				stor := params.GetStorage("0")
				stor.EndPoint = "http://" + server + ":65064"
				params.Save()
			}
		}
		port := utils.SERVER_MAIN_PORT
		if server != "" {
			tokens := strings.Split(server, ":")
			server = tokens[0]
			if len(tokens) == 2 {
				port = utils.ToInt(tokens[1])
			}
		}
		//utils.Debug("Registered user: ", email, ". passwd: ",  password, "; server: ", server, ";  port: ", port)
		isSignup  := command == "signup";
		if r := ClientLogin(server, port, email, password, name, isSignup); r.Error == nil {
			utils.Debug("Login errorCode:", r.ErrorCode)
			if r.ErrorCode  != 0{
				http.Error(w, "", int(r.ErrorCode))
			}else {
				config := utils.ReloadConfig() //Have to reload config, because userID may have changed, so everything needs reset.
				if r.IsNewAccount {
					mode := 0
					config.User = r.UserID
					config.DeviceID = fmt.Sprintf("%d", r.DeviceID)
					config.Mode = mode
					config.Email = email
					if r.ServerAddress != "" && r.ServerAddress != server {
						server = r.ServerAddress
					}
					config.ServerAddress = server
					config.ServerPort = port
					SaveConfig()
				} else {
					config = utils.ReloadConfig()
				}
				//utils.Debug("Repo.count: ", len(config.Repository) , "; to call reconnect() and resetgetall. IsRestore: ", restoreAccount)
				if r.IsRestoreAccount {
					utils.SendToLocal("torestore")
				} else {
					utils.SendToLocal("MSG:Registered")
				}
				go utils.Reconnect(false, r.IsRestoreAccount, nil) //connect GRPC client
				repos := utils.GetRepositoryList()
				if r.IsRestoreAccount || len(repos) > 0 {
					http.Error(w, "", 201)
				} else {
					http.Error(w, "", 200)
				}
			}
		} else {
			if r.ErrorCode == utils.ERROR_CODE_BAD_VERSION {
				http.Error(w, "Error. Version not supported.", utils.HTTP_VERSION_NOT_SUPPORTED)
			}
			if r.ErrorCode == utils.ERROR_CDOE_TIME_OUT {
				//couldn't connect to server
				http.Error(w, "Error. Timeout.", utils.HTTP_TIME_OUT)
			} else {
				utils.Debug("Error is ", r.Error)
				http.Error(w, "Error. Auth failed.", utils.HTTP_UNAUTHORIZED)
			}
		}
	} else if command == "gettoken" {
		if accessToken, err := utils.RetrieveAccessToken(); err == nil {
			utils.Debugf("AccessToken.size: %d", len(accessToken))
			utils.CurrentAccessToken = accessToken
		}
	}

	if len(ret) > 0 {
		len := fmt.Sprintf("%d", len(ret))
		w.Header().Set("Content-Length", len) //it's important to set content-length before w.Write(content)
		w.Write([]byte(ret))
	}
}

func GetUserName(userID uint32) string {
	return ""
}
func getFileSizeString(size int64) string {
	//var d float32;
	//d = float32(S) /1024.0;
	//utils.Debugf("S is %d, %f, d:%f , x:%.2f\n", S, float64(S * 1.0 / 1024), d, 102.1213111);
	if size == 0 {
		return "0"
	} else if size == 1 {
		return "1 byte"
	} else if size < 1024 {
		return fmt.Sprintf("%d Bytes", size)
	} else if size < 1048576 {
		return fmt.Sprintf("%.2f kb", float32(size)/1024)
	} else if size < 1073741824 {
		return fmt.Sprintf("%.2f mb", float32(size)/1048576)
	} else { //if (S < 1000000000000) {
		return fmt.Sprintf("%.2f gb", float64(size)/1073741824)
	}

}

type VersionRow struct {
	Name     string
	ModTime  string
	OpMode   string
	User     string
	FileSize string
	Fkey     string
	Index    string
	Hash     string
	Btn      template.HTML
}
type VersionData struct {
	FolderHash   string
	Start        string
	Size         string
	VersionRows  []VersionRow
	OriginalRows []VersionRow
	HasMore      string
	HasPrev      string
	HasNext      string
}
type RemoteData struct {
	Name    string
	Path    string
	Remotes []string
}

type ChoosePlanUserData struct {
	Email    string
	Name     string
	Phone    string
	UID      string
	Products template.HTML
}

func findGoodFileName(dir string, fileName string) string {
	n := strings.LastIndex(fileName, ".")
	if n > 0 {
		//todo: find right file RemoteName
	}
	return dir + fileName
}

func handleVersionRequest(mode string, folderHash string, hash string, fileNameKey, destFile string, toOpenFile bool) (bool, string) {
	//base := utils.GetTopTreeFolder() + utils.HashToPath(folderHash)
	//binFile := base + ".bin"

	//var row *utils.IndexBinRow
	//if indexString != "" {
	//	index, _ := strconv.Atoi(indexString)
	//	utils.Debug("BinFile: ", binFile, "; index: ", index)
	//	row = utils.GetRowAt(binFile, uint32(index))
	//} else {
	//	row = GetRowByHash(binFile, hash)
	//}
	//if row == nil {
	//	return false, ""
	//}
	fileName, _ := utils.DbGetStringValue(fileNameKey, true) // items.get(row.FileNameKey)
	utils.Debugf("To copy %s in folder %s to downloads. FKey:%s, FileName: %s, destFile:[%s]\n", hash, folderHash, fileNameKey, fileName, destFile)

	if mode == "c" { //copy/open/download
		//if utils.IsFileModeDirectory(row.FileMode) {
		//	go versionRequestCopyFolder(hash, fileName)
		//} else {
			go versionRequestCopyFile(fileName, hash, destFile, toOpenFile)
		//}
		return true, "OK"
	} else if mode == "r" { //restore previous version
		go versionRequestRestoreFile(folderHash, fileName, hash)
	}
	return true, ""
}

func versionRequestRestoreFile(folderHash, fileName, hash string) {
	path := utils.GetFolderFullPath(folderHash)
	utils.Debugf("FolderHash:%s, fileHash:%s\n", folderHash, hash)
	fullFileName := path + "/" + fileName
	utils.Debugf("P:%s, full:%s\n", path, fullFileName)
	CopyObjectFromServerTo(fullFileName, hash)
	RescanFolders([]string{path}, nil, false, 1, false)
	utils.Debug("To send out refreshVersions command...")
	utils.SendToLocal("refreshVersions")
}

func versionRequestCopyFile(fileName, hash, destFile string, toOpenFile bool) (bool, string) {
	usr, err := user.Current()
	if err != nil {
		return false, ""
	}
	ext := GetFileExtension(fileName)
	if ext == "" {
		ext = "obj"
	}
	objFile := utils.GetTopObjectsFolder() + utils.HashToPath(hash) + utils.EXT_OBJ
	extFile := objFile + "." + ext
	if !utils.FileExists(extFile) {
		if !utils.FileExists(objFile) {
			CopyObjectFromServerTo(objFile, hash)
		}
		if !utils.FileExists(objFile) {
			utils.SendToLocal("failDownload:" + fileName)
			return false, ""
		}
		utils.Rename(objFile, extFile)
	}
	objFile = extFile
	utils.Debug("Downloaded file: ", objFile, " and copy it to ", destFile)
	if destFile == "" { //it's "OpenFile operation"
		if toOpenFile {
			utils.SendToLocal("openFile:" + objFile)
		}
		return true, objFile
	} else {
		if destFile == "Downloads" {
			destFile = usr.HomeDir + "/Downloads/" + fileName
		}
		if utils.FileExists(destFile) {
			destFile = findGoodFileName(usr.HomeDir+"/Downloads/", fileName)
			utils.Debug("dest file already exists, create a new destfile: ", destFile)
		}
		//utils.Debugf("Copy file, src:%s, dest:%s\n", srcFile, destFile)
		utils.CopyFile(objFile, destFile)
		if(toOpenFile){
			utils.Debug("To open file:" + destFile)
			utils.SendToLocal("openFile:" + destFile)
		}else {
			utils.SendToLocal("doneDownload:" + destFile)
		}
		return true, destFile
	}
}

func versionRequestCopyFolder(hash, fileName string) {
	base := utils.GetTopTreeFolder() + utils.HashToPath(hash)
	binFile := base + ".bin"
	rows := utils.ReadBin(binFile, utils.FILTER_FILE_ONLY, nil)
	for _, row := range rows {
		fileName, _ := utils.DbGetStringValue(row.FileNameKey, true) // items.get(row.FileNameKey)
		versionRequestCopyFile(fileName, row.ToHashString(), "", false)
	}
	utils.SendToLocal("doneDownload:" + fileName)
}

func createVersionRow(row utils.IndexBinRow, isFirst bool) *VersionRow {
	var r = new(VersionRow)
	r.Name = row.Name
	r.FileSize = getFileSizeString(row.FileSize)  // fmt.Sprintf("%d", row.FileSize);
	r.OpMode = GetOpModeString(row.OperationMode) // fmt.Sprintf("%d", row.OperationMode);
	r.User = GetUserName(row.User)
	r.ModTime = time.Unix(int64(row.LastModified), 0).Format("2006-01-02 15:04:05") //time.RFC3339);// fmt.Sprintf("%s", row.LastModified);
	r.Hash = row.ToHashString()
	r.Fkey = row.FileNameKey
	r.Index = fmt.Sprintf("%d", row.Index)
	var btn string
	if isFirst {
		btn = "<div class=\"file-revisions__current-version\">Current Version</div>"
	} else {
		btn = "<button class=\"restore-revision-button opener\" bid=\"c\" type=\"button\">Copy</button>" +
			"<button class=\"restore-revision-button opener\" bid=\"r\" type=\"button\">Restore</button>"
	}
	r.Btn = template.HTML(btn)
	return r
}

func createVersionLine(row utils.IndexBinRow) string {
	line := ""
	line += getFileSizeString(row.FileSize) + "|"  // fmt.Sprintf("%d", row.FileSize);
	line += GetOpModeString(row.OperationMode) + "|"// fmt.Sprintf("%d", row.OperationMode);
	line += GetUserName(row.User) + "|"
	line += time.Unix(int64(row.LastModified), 0).Format("2006-01-02 15:04:05") + "|"//time.RFC3339);// fmt.Sprintf("%s", row.LastModified);
	line += row.ToHashString()+ "|"
	line += row.FileNameKey+ "|"
	line += fmt.Sprintf("%d", row.Index)+ "|"
	line += row.Name
	return line
}

const (
//main_port = ":50050"
)

func WithKeepAliveDialer() grpc.DialOption {
	return grpc.WithDialer(func(addr string, timeout time.Duration) (net.Conn, error) {
		timeout = time.Duration(10 * time.Second)
		keepAlive := time.Duration(10000 * time.Second)
		d := net.Dialer{Timeout: timeout, KeepAlive: keepAlive}
		return d.Dial("tcp", addr)
	})
}

//	files.Store(fileMeta.fileHash, fileMeta);
//}
//
//func SaveDatFile(fileMeta *utils.FileMeta){
//	ext := utils.EXT_DAT
//	//utils.Debug("Enter save dat file: ", fileMeta)
//	if fileMeta.incomplete != 0 {
//		utils.Debug("FileHash meta is incomplete.")
//		return
//	}
//	fileName := utils.GetTopObjectsFolder() + utils.HashToPath(fileMeta.fileHash) + ext
//	if(fileMeta.C > 0){
//		//utils.Debug("========Save object.dat file: ", fileName, " , CloudSize: ", fileMeta.C, "; fileHash: ", fileMeta.fileHash)
//		utils.AddFileHashSize(fileMeta.fileHash, fileMeta.C)
//	}
//	if(fileMeta.T == 0){
//		if val, f := utils.GetFileID(fileMeta.P) ; f {
//			fileMeta.P += utils.META_PATH_ID_SEPARATOR + val;
//		}
//	}
//	utils.Debug("fileMeta.Path:", fileMeta.P, "; file:", fileName)
//	jsonText := FileMetaToString(fileMeta)
//	utils.WriteString(fileName, jsonText)
//}

func TplHandler(w http.ResponseWriter, r *http.Request) {
	utils.Debug("Enter TplHandler..........")
	utils.Debugf("uri:%s, P:%s \n", r.RequestURI, r.URL.Path)
	//if strings.HasPrefix(r.URL.Path, "/tpl/create_repo.html") {
	//	createRepo(w, r)
	//	//}else if(strings.HasSuffix(r.URL.Path, "/tpl/chooseplan.html")){
	//	//	choosePlan(w,r)
	//} else if strings.HasPrefix(r.URL.Path, "/tpl/create_default_repo.html") {
	//	createDefaultRepo(w, r)
	//if strings.HasPrefix(r.URL.Path, "/tpl/handle_repo.html") {
	//	handleRepo(w, r)
	//	//}else if(strings.HasPrefix(r.URL.P, "/tpl/link_cloud.html")){
	//	//	linkCloud(w, r);
	//} else if strings.HasPrefix(r.URL.Path, "/tpl/versions.html") {
	//	versionsHandler(w, r)
	//} else if strings.HasPrefix(r.URL.Path, "/tpl/password.html") {
	//	changePassword(w, r)
	//} else if strings.HasPrefix(r.URL.Path, "/tpl/mode.html") {
	//	chooseModeOnClient(w, r)
	//} else if strings.HasPrefix(r.URL.Path, "/tpl/localrepos.html") {
	//	chooseLocalRepos(w, r)
	//}
}

func getVersions(w http.ResponseWriter, r *http.Request) string{
	u, _ := url.Parse(r.RequestURI)
	folderHash := u.Query().Get("path")
	istr := u.Query().Get("i")
	fromStr := u.Query().Get("f")
	mode := u.Query().Get("m")
	openFile := u.Query().Get("open")
	hash := u.Query().Get("hash")
	fileNameKey := u.Query().Get("key")
	destPath := u.Query().Get("l")
	utils.Debug("Mode:", mode)
	if len(mode) > 0 {
		toOpen := openFile == "1"
		b, text := handleVersionRequest(mode, folderHash, hash, fileNameKey, destPath, toOpen)
		if !b {
			http.Error(w, "Error. Mode.", utils.HTTP_BAD_REQUEST)
		} else {
			w.Write([]byte(text))
		}
		return ""
	}

	index, _ := strconv.ParseUint(istr, 10, 0)
	//utils.Debugf("P:%s, i:%s, F: %d\n", u.Query().Get("path"), u.Query().Get("i"), from)

	var from int = 0
	if len(fromStr) > 0 {
		from, _ = strconv.Atoi(fromStr)
	}

	psize := 300 //read up to 300 rows

	absPath := utils.GetTopTreeFolder() + utils.HashToPath(folderHash)
	var rows []utils.IndexBinRow
	var original *utils.IndexBinRow
	var hasMore  bool
	//To read log file reversely
	rows, hasMore = ReverseReadLogFileForIndex(absPath, uint32(index), from, psize)
	utils.Debugf("rows.S:%d, absPath:%s, F:%d, hasMore:%v\n", len(rows), absPath, from, hasMore)
	if len(rows) > 1 {
		original = &rows[0]
		if !hasMore {
			n := len(rows) - 1
			rows = rows[:n]
		}
		original, _ = ReadLogFileForIndex(absPath, uint32(index))
	}

	ret := fmt.Sprintf("%v", hasMore) + "\n"
	for _, row := range rows {
		ret += createVersionLine(row) + "\n";
	}
	if original != nil {
		ret += createVersionLine(*original) + "\n"
	}
	utils.Debug("getVersions return:\n" + ret)
	return ret;
}

func versionsHandler(w http.ResponseWriter, r *http.Request) {
	baseFileName := "versions.html"
	filename := path.Join("html", "tpl", baseFileName)
	u, _ := url.Parse(r.RequestURI)
	folderHash := u.Query().Get("path")
	istr := u.Query().Get("i")

	mode := u.Query().Get("m")
	openFile := u.Query().Get("open")
	hash := u.Query().Get("hash")
	fromStr := u.Query().Get("f")
	destPath := u.Query().Get("l")
	utils.Debug("Mode:", mode)
	if len(mode) > 0 {
		toOpen := openFile == "1"
		b, text := handleVersionRequest(mode, folderHash, hash, istr, destPath, toOpen)
		if !b {
			http.Error(w, "Error. Mode.", utils.HTTP_BAD_REQUEST)
		} else {
			w.Write([]byte(text))
		}
		return
	}
	if len(folderHash) == 0 || len(istr) == 0 {
		http.Error(w, "Error. Empty hash", utils.HTTP_BAD_REQUEST)
		return
	}
	var from int = 0
	if len(fromStr) > 0 {
		from, _ = strconv.Atoi(fromStr)
	}

	psize := 10
	index, _ := strconv.ParseUint(istr, 10, 0)
	utils.Debugf("P:%s, i:%s, F: %d\n", u.Query().Get("path"), u.Query().Get("i"), from)

	absPath := utils.GetTopTreeFolder() + utils.HashToPath(folderHash)
	var rows []utils.IndexBinRow
	var original *utils.IndexBinRow
	var hasMore, noLogFile bool
	//if(!utils.FileExists(absPath + ".log")){
	//	//no log file, only the original version exists
	//	noLogFile = true;
	//	original = ReadBinFileForIndex(absPath, ".bin", uint32(index));
	//}else {
	noLogFile = false
	//To read log file reversely
	rows, hasMore = ReverseReadLogFileForIndex(absPath, uint32(index), from, psize)
	utils.Debugf("rows.S:%d, absPath:%s, F:%d, hasMore:%v\n", len(rows), absPath, from, hasMore)
	if len(rows) > 1 {
		original = &rows[0]
		if !hasMore {
			n := len(rows) - 1
			rows = rows[:n]
		}
		original, _ = ReadLogFileForIndex(absPath, uint32(index))
	}
	//original = ReadBinFileForIndex(absPath, ".bin_", uint32(index))
	//}
	var orows []VersionRow
	if original != nil {
		original.OperationMode = utils.MODE_NEW_FILE
		r := createVersionRow(*original, noLogFile)
		orows = append(orows, *r)
	}
	utils.Debugf("filename: %s, rows.S: %d, hasMore: %v\n", filename, len(rows), hasMore)
	var vrows []VersionRow

	isFirst := from == 0
	for _, row := range rows {
		r := createVersionRow(row, isFirst)
		isFirst = false
		vrows = append(vrows, *r)
	}
	utils.Debug("versions.size: ", len(vrows))
	var hasMoreStyle, hasNext, hasPrev string
	hasMoreStyle = "text-align:center"
	hasNext = ""
	if !hasMore {
		if from == 0 {
			hasMoreStyle = "display: none"
		} else {
			hasNext = "display: none"
		}
	}
	if from == 0 {
		hasPrev = "display: none"
	}

	data := VersionData{
		FolderHash:   folderHash,
		Start:        fmt.Sprintf("%d", from),
		Size:         fmt.Sprintf("%d", psize),
		VersionRows:  vrows,
		OriginalRows: orows,
		HasMore:      hasMoreStyle,
		HasPrev:      hasPrev,
		HasNext:      hasNext,
	}
	tmpl, err := template.ParseFiles(filename)
	if err != nil {
		panic(err)
	}
	err = tmpl.ExecuteTemplate(w, baseFileName, data)
	if err != nil {
		panic(err)
	}
}

//func createRepo(w http.ResponseWriter, r *http.Request) {
//	baseFileName := "create_repo.html"
//	filename := path.Join("html", "tpl", baseFileName)
//	utils.Debug("In createRepo, fileName: ", filename)
//	utils.Debug("Enter create repo. url: ", r.RequestURI) // /rest/saverepo?txtFakeText=vm&name=repo1&encrypted=on&remote=gd2&newremote=googledrive&rname=&nfstext=
//
//	tmpl, err := template.ParseFiles(filename)
//	if err != nil {
//		utils.Debug(err)
//	}
//	u, _ := url.Parse(r.RequestURI)
//
//	remotes := utils.GetRemotesIncludingTemps() //  []string{"Google", "DBox"};//"'GoogleDrive', 'DBox'";
//	name := u.Query().Get("name")
//	b2Acct := u.Query().Get("b2acct")
//	accessKeyID := u.Query().Get("keyid")
//	if name != "" && accessKeyID == "" {
//		utils.AuthName = name
//	}
//	utils.Debug("Remote.size: ", len(remotes.Remote))
//	utils.Debug("~~~~~~~~ In CreateRepo. RemoteName: ", name, "; AuthToken: ", utils.AuthToken, "; AuthName:", utils.AuthName)
//	nfs := u.Query().Get("nfs")
//	if nfs != "" {
//		remotes = utils.SaveNewRemote(remotes, name, utils.REMOTE_TYPE_LOCAL_NFS, nfs, nil)
//	} else if b2Acct != "" {
//		m := make(map[string]string)
//		m["accessKey"] = u.Query().Get("accesskey")
//		m["account"] = b2Acct
//		m["bucket"] = u.Query().Get("bucket")
//		m["endpoint"] = "https://api.backblazeb2.com"
//		remotes = utils.SaveNewRemote(remotes, name, utils.REMOTE_TYPE_B2, "", m)
//	} else if accessKeyID != "" {
//		m := make(map[string]string)
//		m["accessKey"] = u.Query().Get("accesskey")
//		m["accessKeyID"] = accessKeyID
//		m["bucket"] = u.Query().Get("bucket")
//		m["endpoint"] = u.Query().Get("endpoint")
//		m["region"] = u.Query().Get("region")
//		remotes = utils.SaveNewRemote(remotes, name, utils.REMOTE_TYPE_S3, "", m)
//	} else if utils.AuthName != "" && utils.AuthToken != "" {
//		m := make(map[string]string)
//		m["token"] = utils.AuthToken
//		remotes = utils.SaveNewRemote(remotes, utils.AuthName, utils.RemoteType, "", m)
//	}
//	var keys []string
//	if utils.LoadConfig().IsOfficialSite() {
//		keys = append(keys, "AnySync.net") //value "AnySync.net" must match the one in createRepoFromRequest func
//	} else {
//		keys = append(keys, "My Server") //value "My Server" must match the one in createRepoFromRequest func
//	}
//	for _, val := range remotes.Remote {
//		if val.Name == utils.REMOTE_TYPE_SERVER_NAME || val.Name == utils.REMOTE_STORAGE_NAME {
//			continue
//		}
//		k := val.Name + " (" + val.Type + ")"
//		keys = append(keys, k)
//	}
//
//	data := RemoteData{
//		Name:    "",
//		Path:    "",
//		Remotes: keys,
//	}
//	utils.Debug("Before execute template, remotes.len: ", len(keys))
//	err = tmpl.ExecuteTemplate(w, baseFileName, data)
//	if err != nil {
//		panic(err)
//	}
//}

//func choosePlan(w http.ResponseWriter, r *http.Request) {
//	d := make(map[string][]byte)
//	utils.Debug("Enter choose plan")
//	if response, err := utils.CallSendData("getUserInfo", nil, d, nil, nil); err == nil {
//		utils.Debug("response.Data:", response.Data)
//		ps := string(response.Data["products"]);
//		products := strings.Split(ps, ",");
//		options := ""
//		for _,p := range products {
//			tokens := strings.Split(p, ";")
//			size := tokens[0];
//			price := tokens[1]
//			options +=  "<option value='/p" + size + "'>" + size + " GB Cloud Storage, $" + price + "USD/month</option>\n"; //<option value="us-east-2" >US East (Ohio) Region</option>
//		}
//		w.Write(response.Data["name"])
//		data := ChoosePlanUserData{
//			Name:    string(response.Data["name"]),
//			Email:    string(response.Data["email"]),
//			UID:    string(response.Data["uid"]),
//			Phone: string(response.Data["phone"]),
//			Products: template.HTML(options),
//		}
//		baseFileName := "choose_plan.html"
//		filename := path.Join("html", "tpl", baseFileName)
//		utils.Debug("In chooseplan, fileName: ", filename)
//		tmpl, err := template.ParseFiles(filename)
//		if err != nil {
//			utils.Debug(err)
//		}
//		err = tmpl.ExecuteTemplate(w, baseFileName, data)
//		if err != nil {
//			utils.Debug(err)
//		}
//
//	}else{
//		utils.Debug("getUserInfo error:", err)
//	}
//}

func getUserInfo() string {
	m := utils.GetUserInfo("")
	if m != nil {
		utils.Debug("response.Data:", m)
		text := "u=" + string(m["uid"]) + "&" + "email=" + string(m["email"])
		return text
	} else {
		return ""
	}
}

//func createDefaultRepo(w http.ResponseWriter, r *http.Request) {
//	baseFileName := "create_default_repo.html"
//	filename := path.Join("html", "tpl", baseFileName)
//	utils.Debug("In createRepo, fileName: ", filename)
//	utils.Debug("Enter create repo. url: ", r.RequestURI) // /rest/saverepo?txtFakeText=vm&name=repo1&encrypted=on&remote=gd2&newremote=googledrive&rname=&nfstext=
//
//	tmpl, err := template.ParseFiles(filename)
//	if err != nil {
//		panic(err)
//	}
//	u, _ := url.Parse(r.RequestURI)
//
//	remotes := utils.GetRemotesIncludingTemps() //  []string{"Google", "DBox"};//"'GoogleDrive', 'DBox'";
//	name := u.Query().Get("name")
//	b2Acct := u.Query().Get("b2acct")
//	accessKeyID := u.Query().Get("keyid")
//	if name != "" && accessKeyID == "" {
//		utils.AuthName = name
//	}
//	utils.Debug("Remote.size: ", len(remotes.Remote))
//	utils.Debug("~~~~~~~~ In CreateRepo. RemoteName: ", name, "; AuthToken: ", utils.AuthToken, "; AuthName:", utils.AuthName)
//	nfs := u.Query().Get("nfs")
//	if nfs != "" {
//		remotes = utils.SaveNewRemote(remotes, name, utils.REMOTE_TYPE_LOCAL_NFS, nfs, nil)
//	} else if b2Acct != "" {
//		m := make(map[string]string)
//		m["accessKey"] = u.Query().Get("accesskey")
//		m["account"] = b2Acct
//		m["bucket"] = u.Query().Get("bucket")
//		m["endpoint"] = "https://api.backblazeb2.com"
//		remotes = utils.SaveNewRemote(remotes, name, utils.REMOTE_TYPE_B2, "", m)
//	} else if accessKeyID != "" {
//		m := make(map[string]string)
//		m["accessKey"] = u.Query().Get("accesskey")
//		m["accessKeyID"] = accessKeyID
//		m["bucket"] = u.Query().Get("bucket")
//		m["endpoint"] = u.Query().Get("endpoint")
//		m["region"] = u.Query().Get("region")
//		remotes = utils.SaveNewRemote(remotes, name, utils.REMOTE_TYPE_S3, "", m)
//	} else if utils.AuthName != "" && utils.AuthToken != "" {
//		m := make(map[string]string)
//		m["token"] = utils.AuthToken
//		remotes = utils.SaveNewRemote(remotes, utils.AuthName, utils.RemoteType, "", m)
//	}
//	usr, err := user.Current()
//	defaultPath := usr.HomeDir
//	if utils.IsWindows() {
//		defaultPath += "\\AnySync"
//	} else {
//		defaultPath += "/AnySync"
//	}
//	if !utils.FileExists(defaultPath) {
//		utils.Mkdir(defaultPath)
//	}
//	data := RemoteData{
//		Name: "",
//		Path: defaultPath,
//	}
//	err = tmpl.ExecuteTemplate(w, baseFileName, data)
//	if err != nil {
//		panic(err)
//	}
//}

//func handleRepo(w http.ResponseWriter, r *http.Request) {
//	u, _ := url.Parse(r.RequestURI)
//	utils.Debug("handleRepo.Request: ", u.RequestURI())
//	remote := u.Query().Get("newremote")
//	if remote != "" && remote != utils.REMOTE_TYPE_S3 && remote != utils.REMOTE_TYPE_B2 {
//		utils.AuthToken = ""
//		utils.AuthName = u.Query().Get("rname")
//		utils.RemoteType = remote
//		authUrl := utils.GetAuthUrl(remote)
//		go utils.StartServer(remote)
//		utils.Debug("AuthURL: ", authUrl, ";\nAuthName:", utils.AuthName)
//		w.Write([]byte(authUrl))
//	}
//	//http.Redirect(w, r, authUrl, 301)
//}

func SaveRepo(w http.ResponseWriter, r *http.Request) {
	utils.Debug("Enter save repo. url: ", r.RequestURI) // /rest/saverepo?txtFakeText=vm&name=repo1&encrypted=on&remote=gd2&newremote=googledrive&rname=&nfstext=
	u, _ := url.Parse(r.RequestURI)
	utils.Debug("Request: ", u.RequestURI())
	name := u.Query().Get("name")

	if repoExists(name) {
		http.Error(w, "no name", 406)
		return
	}
	doSaveRepo(r)
}

func doSaveRepo(r *http.Request) {
	u, _ := url.Parse(r.RequestURI)
	encrypted := u.Query().Get("encrypted") //value is "on" if it's checked; otherwise ""
	isEncrypted := encrypted == "on"
	name := u.Query().Get("name")
	utils.Debug("repo name: ", name, "; encrypted: ", encrypted)
	localFolder := u.Query().Get("local")
	utils.Debug("LocalFolder in URL: ", localFolder)
	SaveRepoWithNameAndScan(name, localFolder, isEncrypted, true)
}

//func serverRemoteExists()bool {
//	rms := utils.GetRemotesIncludingTemps();
//	for _, r := range rms.Remote {
//		if (r.RemoteName == utils.REMOTE_TYPE_SERVER_NAME) {
//			return true;
//		}
//	}
//	return false;
//}

func getStates(w http.ResponseWriter, r *http.Request) {
	utils.Debug("Enter getStates. url: ", r.RequestURI)
	u, _ := url.Parse(r.RequestURI)
	utils.Debug("Request: ", u.RequestURI())
	var text string
	state := SyncState.GetValue()
	if state == SYNC_STATE_SYNCING {
		text = fmt.Sprintf("%d|%s", SyncState, SyncingRepos)
	} else {
		text = fmt.Sprintf("%d", SyncState)
	}
	w.Write([]byte(text))
}

func getRepoSize(w http.ResponseWriter, r *http.Request) string {
	utils.Debug("Enter getStates. url: ", r.RequestURI)
	u, _ := url.Parse(r.RequestURI)
	utils.Debug("Request: ", u.RequestURI())
	hash := u.Query().Get("hash")
	var text string

	size, fileCount := GetAllSize(hash)
	text = fmt.Sprintf("%d\n%d", size, fileCount)

	return text
}

//func getSetting(w http.ResponseWriter, r *http.Request) string {
//	utils.Debug("Enter getSetting. url: ", r.RequestURI)
//	u, _ := url.Parse(r.RequestURI)
//	utils.Debug("Request: ", u.RequestURI())
//	name := u.Query().Get("name")
//	var ret string
//	config := utils.LoadConfig()
//	if name == "rate" {
//		ret = fmt.Sprintf("%d", config.RateLimit)
//	} else if name == "proxy" {
//		ret = config.Proxy.ToString()
//	}
//	return ret
//}

func getRepos(w http.ResponseWriter, r *http.Request) string {
	repos := utils.GetRepositoryList()
	u, _ := url.Parse(r.RequestURI)
	nameOnly := u.Query().Get("name") != "";
	utils.Debug("nameOnly:", nameOnly , "; name:" , u.Query().Get("name"))
	var result string
	var ret []*utils.Repository
	var names string;
	for _, r := range repos {
		if r.Hash == utils.SHARED_HASH {
			subPath := utils.HashToPath(utils.SHARED_HASH)
			binFile := utils.GetTopTreeFolder() + subPath + ".bin"
			fileSize := utils.FileSize(binFile)
			if (fileSize / utils.FILE_INFO_BYTE_COUNT) == 1 {
				continue
			}
		}
		ret = append(ret, r)
		if(nameOnly){
			names = names + r.Name + "\n"
		}
	}
	if nameOnly {
		utils.Debug("getRepos.return: <" + names + ">")
		return names;
	}else {
		if bs, err := json.Marshal(ret); err != nil {
			return ""
		} else {
			utils.Debug("repos are\n", string(bs))
			result = string(bs)
		}
		return result
	}
}

func getRepo(w http.ResponseWriter, r *http.Request) string {
	u, _ := url.Parse(r.RequestURI)
	hash := u.Query().Get("hash")

	repos := utils.GetRepositoryList()
	var ret string
	for _, r := range repos {
		if r.Hash == hash {
			for _, remote := range r.Remote {
				name := remote.Name
				if remote.Type == utils.REMOTE_TYPE_SERVER {
					name = "My Server"
				} else if remote.Type == utils.REMOTE_TYPE_OFFICIAL {
					name = "AnySync.net"
				}
				t := fmt.Sprintf("RemoteName: %s\nIs Encrypted: %v\n", name, r.EncryptionLevel > 0)
				ret += t
			}
		}
	}

	return ret
}

func getFileNameByKey(w http.ResponseWriter, r *http.Request) string {
	u, _ := url.Parse(r.RequestURI)
	name := u.Query().Get("name")
	if bs, found := utils.DbGetStringValue(name, true); !found {
		http.Error(w, "Error", utils.HTTP_NOT_FOUND)
		return ""
	} else {
		//utils.Debug("FileNameKey: ", name , "; result: ", string(bs))
		return string(bs)
		//w.Write([]byte(string(bs)));
	}
}
func getFileNamesByKey(w http.ResponseWriter, r *http.Request) string {
	bodyBytes, _ := ioutil.ReadAll(r.Body)
	names := string(bodyBytes)
	//utils.Debug("names: ", names);

	tokens := strings.Split(names, ",")
	ret := ""
	m := utils.DbGetStringValues(tokens, true)
	for k, v := range m{
		if ret != "" {
			ret += "\n"
		}
		ret += k + "=" + string(v)
	}
	//for _, name := range tokens {
	//	if bs, found := utils.DbGetStringValue(name, true); found {
	//		if ret != "" {
	//			ret += "\n"
	//		}
	//		ret += name + "=" + string(bs)
	//	}
	//}
	u, _ := url.Parse(r.RequestURI)
	folderHash := u.Query().Get("folder")
	if len(folderHash) > 0 {
		go RestoreThumbnails(folderHash)
	}
	return ret
}

func getSettings() string {
	if !utils.CurrentFileExists() {
		return ""
	}
	config := utils.LoadConfig()
	local := ""
	rs := utils.GetRepositoryList()
	repos := ""

	repoHashes := ""
	encrypted := "";
	if len(rs) > 0 {
		for _, r := range rs {
			if local == "" {
				local = r.Local
				repos = r.Name
				repoHashes = r.Hash;
				if(r.EncryptionLevel > 0) {
					encrypted = "Yes"
				}else{
					encrypted = "No"
				}
			} else {
				local += ", " + r.Local
				repos += ", " + r.Name
				repoHashes += ", " + r.Hash
				if(r.EncryptionLevel > 0) {
					encrypted +=  ", Yes"
				}else{
					encrypted = ", No"
				}

			}
		}
	}
	cloudStorage := utils.CountTotalSize(true)
	result := ""
	result += fmt.Sprintf("server=%s\n", utils.LoadAppParams().Server)
	result += fmt.Sprintf("rate=%d\n", config.RateLimit)
	result += fmt.Sprintf("mode=%d\n", config.Mode)
	result += fmt.Sprintf("deviceID=%s\n", config.DeviceID)
	result += fmt.Sprintf("scaninterval=%d\n", config.ScanInterval)
	result += fmt.Sprintf("selectedfolders=%s\n", config.SelectedFolders)
	result += fmt.Sprintf("localFolders=%s\n", local)
	result += fmt.Sprintf("cloudStorage=%s\n", cloudStorage)
	if(utils.CurrentUser != nil) {
		t := time.Unix(int64(utils.CurrentUser.Expiry), 0).Format("2006-01-02")
		result += fmt.Sprintf("expiry=%s\n", t)
		result += fmt.Sprintf("acct=%d\n", utils.CurrentUser.AccountType)
		result += fmt.Sprintf("quota=%d\n", utils.CurrentUser.Quota)
	}
	result += fmt.Sprintf("repos=%s\n", repos)
	result += fmt.Sprintf("repoHashes=%s\n", repoHashes)
	result += fmt.Sprintf("encrypted=%s\n", encrypted)

	result += fmt.Sprintf("logLevel=%d\n", config.LogLevel)
	result += fmt.Sprintf("proxy=%s\n", config.Proxy.ToString())
	result += fmt.Sprintf("email=%s\n", config.Email)
	result += fmt.Sprintf("server=%s:%d\n", config.ServerAddress, config.ServerPort)
	result += fmt.Sprintf("maxage=%d\n", config.MaxAge)
	result += fmt.Sprintf("maxsize=%d\n", config.MaxSize)
	result += fmt.Sprintf("minage=%d\n", config.MinAge)
	//result += fmt.Sprintf("minsize=%d\n", config.MinSize)
	result += fmt.Sprintf("threadcount=%d\n", config.ThreadCount)
	result += fmt.Sprintf("included=%s\n", config.Included)
	result += fmt.Sprintf("excluded=%s\n", config.Excluded)

	//utils.Debug("DeviceID: ", config.DeviceID, "; settings:", result)
	return result
}

func updateSetting(w http.ResponseWriter, r *http.Request) {
	utils.Debug("Enter updateSetting. url: ", r.RequestURI)
	u, _ := url.Parse(r.RequestURI)
	utils.Debug("Request: ", u.RequestURI())
	config := utils.LoadConfig()
	changed := false
	for key, val := range u.Query() {
		if key == "rate" {
			if i, err := strconv.Atoi(val[0]); err == nil {
				config.RateLimit = i
				changed = true
			}
		} else if key == "mode" {
			if i, err := strconv.Atoi(val[0]); err == nil {
				config.Mode = i
				changed = true
			}
		} else if key == "excluded" {
			config.Excluded = val[0]
			changed = true
		} else if key == "included" {
			config.Included = val[0]
			changed = true
		} else if key == "maxage" {
			config.MaxAge = int64(utils.ToInt(val[0]))
			changed = true
		} else if key == "maxsize" {
			config.MaxSize = int64(utils.ToInt(val[0]))
			changed = true
		} else if key == "threadcount" {
			config.ThreadCount = utils.ToInt(val[0])
			changed = true
		} else if key == "scaninterval" {
			config.ScanInterval = utils.ToInt(val[0])
			changed = true
		} else if key == "selectedfolders" {
			config.SelectedFolders = val[0]
			changed = true
		} else if key == "minage" {
			config.MinAge = int64(utils.ToInt(val[0]))
			changed = true
			//} else if key == "minsize" {
			//	config.MinSize = int64( utils.ToInt(val[0]) );
			//	changed = true
		} else if key == "device" {
			config.DeviceID = val[0]
			changed = true
		} else if key == "proxy" {
			config.Proxy.FromString(val[0])
			changed = true
		}
	}

	if changed {
		SaveConfig()
	}
}

func sendStatsInfo() {
	//utils.Debug("Enter getStats. url: ", r.RequestURI)
	//u, _ := url.Parse(r.RequestURI)
	//utils.Debug("Request: ", u.RequestURI())
	//text := fs.Stats.String();


	//bs, n, files := accounting.GetStatsInfo()
	//text := fmt.Sprintf("%d\n%d\n%s", bs, n, files)
	//utils.SendToLocal(utils.MSG_PREFIX + text)

	//utils.Debug("Stats: <", text, ">")
	//w.Write([]byte(text))
}

//func askRestore(w http.ResponseWriter, r *http.Request, mode int) {
//	if(mode == 0){
//		//remove existing and download all
//		dirs := GetLocalFolders();
//		for _, dir :=range dirs{
//			utils.RemoveAllFiles(dir);
//		}
//		RestoreToConfiguredPlace();
//	}else if(mode == 1){
//		//copy new
//		RestoreToConfiguredPlace();
//	}else{
//		config := utils.LoadConfig();
//		config.Mode = utils.CONFIG_MODE_PLACEHOLDER;
//		for i, _ := range config.Repository{
//			config.Repository[i].Local = ""
//		}
//		SaveConfig();
//		//switch to upload only mode
//	}
//	utils.Debug("Mode: <", mode, ">")
//	w.Write([]byte("OK"))
//	utils.SendToLocal("ready")
//}
func updateConfigLocal(w http.ResponseWriter, r *http.Request) { //url:  "http://127.0.0.1:65066/rest/updatelocal?mode=r&txtFakeText0=t+t+&txtFakeText1=t+t++&local0=%2FUsers%2FIMAC%2Ft%20t&local1=%2FUsers%2FIMAC%2Ft%20t"
	go toRestore(r)
	w.Write([]byte("OK"))
}

func verifyRepo(w http.ResponseWriter, r *http.Request, quick bool) string {
	u, _ := url.Parse(r.RequestURI)
	hash := u.Query().Get("hash")
	config := utils.LoadConfig()
	if config.Mode == utils.CONFIG_MODE_PLACEHOLDER {
		return "OK"
	}
	if quick {
		go quickVerify(hash)
	} else {
		go deepVerify(hash)
	}
	go utils.SendToLocal("working")
	return "WAIT"
}

func quickVerify(hash string) {
	b, totalChangedRows, files := doQuickVerify(hash)
	if b {
		utils.Debug("TotalChanges:", totalChangedRows, "; files: ", files)
		utils.SendToLocal(fmt.Sprintf("qverify1:%d:%s", totalChangedRows, files))
	} else {
		utils.SendToLocal("qverify0")
	}
	utils.Debug("Return from startVerify")
}

func doQuickVerify(hash string) (bool, int, []string) {
	path := utils.GetFolderFullPath(hash)
	utils.Debug("Path is", path)
	var files[]string;
	folderEx, _, _ := foldersToFolderEx([]string{path}, false)
	if len(folderEx) > 0 {
		r, _:= rescanFolderEx(folderEx, "", nil, 2, utils.REPO_SHARE_STATE_ALL, false, true)
		if r != nil && len(r.modifiedFolders) > 0 {
			utils.Debug("Modified folder.size: ", len(r.modifiedFolders))
			//r.countChanges()
			totalChangedRows := 0
			filesCount := 0
			for _, m := range r.modifiedFolders {
				utils.Debugf("Local Hash:%s, relativePath:%v\n", m.FolderHash, m.RelativePath)
				p := m.RelativePath[5:] //remove "Root/" in Root/AnySync/...
				for _, row := range m.Rows {
					files = append(files, p + "/" + row.FileName)
					filesCount++
					if(filesCount > 100){
						return true, totalChangedRows, files
					}
				}
				totalChangedRows += len(m.Rows)
			}
			return true, totalChangedRows, files
		} else {
			utils.Debug("returned r is null")
			return false, 0, files;
		}
	}
	return false, 0,files
}

func deepVerify(hash string) {
	changes := checkChanges(hash,true)
	var  files []string
	utils.SendToLocal(utils.MSG_PREFIX + "Check if all files have been synced...")

	changes.Range(func(k, v interface{}) bool {
		folder := k.(string)
		files = append(files, folder)
		return true
	})
	//b, totalChangedRows, files := doQuickVerify(hash)

	if len(files) > 0 {
		//utils.Debug("TotalChanges:", totalChangedRows, "; files: ", strings.Join(files, ","))
		utils.SendToLocal(fmt.Sprintf("qverify1:%d:%s", len(files), strings.Join(files, ",")))
		return
	}
	//now check cloud files
	utils.SendToLocal(utils.MSG_PREFIX + "To verify cloud files...")

	notsynced := verifyRepositories()
	if len(notsynced) > 0 || len(files) > 0{
		notsynced = append(notsynced, files...)
		n := len(notsynced)
		msg := fmt.Sprintf("qverify1:%d:%s", n, strings.Join(notsynced, ",") );
		//fmt.Println("unsynced:", msg)
		utils.SendToLocal(msg)
	}else{
		utils.SendToLocal("qverify0")
	}
}
func fixRepo(w http.ResponseWriter, r *http.Request) string {
	u, _ := url.Parse(r.RequestURI)
	hash := u.Query().Get("hash")
	folder := u.Query().Get("folder")
	utils.Debug("To fix, folder:", folder, "; hash:", hash)
	go FixRepo(folder, hash)
	return "OK"
}

func updatePassword(w http.ResponseWriter, r *http.Request) {
	u, _ := url.Parse(r.RequestURI)
	utils.Debug("Request: ", u.RequestURI())
	oldVal := u.Query().Get("old")
	newVal := u.Query().Get("new")
	utils.Debug("Old:", oldVal, ", new: ", newVal)

	c, conn, err := utils.NewGrpcClient()
	if err != nil {
		utils.Warnf("did not connect: %v", err)
		w.Write([]byte("NO"))
		return
	}
	defer conn.Close()
	ret := false
	keyFile := utils.GetAppHome() + "data/" + utils.MASTER_KEY_FILE
	if m, err := utils.DecryptMasterKeys([]byte(oldVal), keyFile); err == nil {
		keyFileBak := keyFile + "." + utils.GenerateRandomHash()
		utils.Rename(keyFile, keyFileBak)
		rsaPub := m["pub"]
		encKey := m["enc"]
		rsaPriv := m["priv"]
		authKey := m["auth"]
		deviceID := utils.ToUint32(utils.CurrentConfig.DeviceID)
		if _, _, err := utils.SaveKeys([]byte(newVal), true, encKey, authKey, utils.CurrentAccessToken, rsaPub, rsaPriv, deviceID, keyFile); err == nil {
			if err = sendMasterKeyFile(utils.CurrentConfig.User, deviceID, utils.CurrentAccessToken, c); err == nil {
				ret = true
			}
		}
		if !ret { //if error occurs, revert back.
			utils.Rename(keyFileBak, keyFile)
		} else {
			utils.RemoveFile(keyFileBak)
		}
	}
	if ret {
		w.Write([]byte("OK"))
	} else {
		w.Write([]byte("NO"))
	}
}

func chooseModeOnClient(w http.ResponseWriter, r *http.Request) {
	baseFileName := "mode.html"
	filename := path.Join("html", "tpl", baseFileName)
	utils.Debug("In createRepo, fileName: ", filename)
	utils.Debug("Enter create repo. url: ", r.RequestURI) // /rest/saverepo?txtFakeText=vm&name=repo1&encrypted=on&remote=gd2&newremote=googledrive&rname=&nfstext=

	tmpl, err := template.ParseFiles(filename)
	if err != nil {
		panic(err)
	}
	keys := []string{}
	list := utils.GetAllRepositoryList(false)
	for _, val := range list {
		keys = append(keys, val.Name)
	}
	data := RemoteData{
		Remotes: keys,
	}
	err = tmpl.ExecuteTemplate(w, baseFileName, data)
	if err != nil {
		panic(err)
	}

}

func chooseLocalRepos(w http.ResponseWriter, r *http.Request) {
	baseFileName := "localrepos.html"
	filename := path.Join("html", "tpl", baseFileName)
	utils.Debug("In createRepo, fileName: ", filename)
	utils.Debug("Enter create repo. url: ", r.RequestURI) // /rest/saverepo?txtFakeText=vm&name=repo1&encrypted=on&remote=gd2&newremote=googledrive&rname=&nfstext=

	tmpl, err := template.ParseFiles(filename)
	if err != nil {
		panic(err)
	}
	keys := []string{}
	list := utils.GetAllRepositoryList(false)
	for _, val := range list {
		keys = append(keys, val.Name)
	}
	data := RemoteData{
		Remotes: keys,
	}
	err = tmpl.ExecuteTemplate(w, baseFileName, data)
	if err != nil {
		panic(err)
	}
}

func changePassword(w http.ResponseWriter, r *http.Request) {
	baseFileName := "password.html"
	filename := path.Join("html", "tpl", baseFileName)
	utils.Debug("In createRepo, fileName: ", filename)
	utils.Debug("Enter create repo. url: ", r.RequestURI) // /rest/saverepo?txtFakeText=vm&name=repo1&encrypted=on&remote=gd2&newremote=googledrive&rname=&nfstext=

	tmpl, err := template.ParseFiles(filename)
	if err != nil {
		panic(err)
	}
	keys := []string{}
	list := utils.GetAllRepositoryList(false)
	for _, val := range list {
		keys = append(keys, val.Name)
	}
	data := RemoteData{
		Remotes: keys,
	}
	err = tmpl.ExecuteTemplate(w, baseFileName, data)
	if err != nil {
		panic(err)
	}
}

func deleteSelectedFolders(fs string) string{
	folders := strings.Split(fs, ",")
	repos := utils.GetRepositoryMap()
	for  _, k := range folders{
		pos := strings.Index(k, "/")
		repoName := k[0 : pos]
		r := repos[repoName]
		absPath := r.Local + "/" + k[pos + 1:]
		utils.RemoveAllFiles(absPath)
	}
	return "OK"
}

