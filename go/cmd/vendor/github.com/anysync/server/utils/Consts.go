// Copyright (c) 2020, Yanbin (Henry) Zheng <ybzheng@gmail.com>
// All rights reserved.
//
// Use of this source code is governed by a AGPLv3 license that can be
// found in the LICENSE file.

package utils

import (
	"os/user"
	"strings"
)
type AsErrorCode uint32;
const (
	VERSION = "1"
	MAIN_PORT = ":65065"
	NULL_FILE_KEY = ("00000000000000000000000000000000000000000000000000000000")
	ROOT_NODE = "Root"
	ROOT_SHARE_NODE = "Share"
	TOP_DIR = "AnySyncNet"
	DEFAULT_BUCKET = "anysyncnet1"
	FILE_NAME_KEY_BYTE_COUNT = 28

	//Index.4|FileNameKey.16|Offset.4|CreateTime.4|FileMode.4|Timestamp.4|LastModified.4|size.8|opMode.1|user.4|Hash.28
	FILE_INFO_BYTE_COUNT = 93  // 65 + (FILE_NAME_KEY_BYTE_COUNT - 4)

	FILE_OFFSET_INDEX = 4 + FILE_NAME_KEY_BYTE_COUNT         //Index.4|FileNameKey.16|Offset.4|CreateTime.4|FileMode.4
	FILE_MODE_INDEX   = 4 + FILE_NAME_KEY_BYTE_COUNT + 4 + 4 //Index.4|FileNameKey.16|Offset.4|CreateTime.4|FileMode.4

	FILE_INFO_BYTE_HEADER_COUNT = 16 + (FILE_NAME_KEY_BYTE_COUNT - 4) //40: Index, FileNameKey, Offset and CreateTime fields

	FILE_OPMODE_POS = FILE_INFO_BYTE_HEADER_COUNT + 20 // + FileMode.4 Timestamp.4|LastModified.4|sizeAndOpMode.8

	DEFAULT_OPERATION_MODE = 255

	/** max number of changes */
    MAX_CHANGE_COUNT_CLIENT = 10000
    MAX_CHANGE_COUNT_SERVER = 20000
    SERVER_CHANGE_TOO_MANY = 1

	SERVER_LOG_BIN_ROW_SIZE = 40

	SMALL_FILE_SIZE_THRESHOLD    = 1024 * 1024      //1MB
	XDIFF_FILE_SIZE_LOWER        = 2 * 1024 * 1024   //2MB
	XDIFF_FILE_SIZE_UPPER        = 20 * 1024 * 1024 //20MB
	PACK_FILE_SIZE_MIN_THRESHOLD = 1 *  1024 * 1024
	PACK_FILE_SIZE_MAX_THRESHOLD = 20 * PACK_FILE_SIZE_MIN_THRESHOLD;// 18 * 1024 * 1024 //20MB.
	PACK_FILE_MIN_FILE_COUNT     = 8
	CHUNKING_FILE_SIZE_THRESHOLD = 20 * 1024 * 1024 //20MB // 512*1024*1024

	ACTION_UPDATE = "update"
	ACTION_DOWNLOAD = "download"

	ACTION_RESET_GET_ALL = "ResetGetAll"
	ACTION_SHARE_FOLDER = "ShareFolder"
	ACTION_SHARE_ACTION = "ShareAction"
	ACTION_VERIFY = "Verify"
	ACTION_ADD_USER = "AddUser"
	ACTION_GET_USER = "GetUser"
	ACTION_ACCT_TYPE_CHANGE = "AcctChange"
	ACTION_ACK = "Ack"

	FILE_META_TYPE_REGULAR = 0;
	FILE_META_TYPE_PACK = 1;
	FILE_META_TYPE_PACK_ITEM = 2;
	FILE_META_TYPE_CHUNKS = 3;
	FILE_META_TYPE_CHUNK_ITEM = 4;
	FILE_META_TYPE_THUMBNAIL = 5;

	FILE_META_TYPE_DIFF = 100;

	FILE_META_TYPE_DELETED = 10000;

	HTTP_BAD_REQUEST = 400
	HTTP_UNAUTHORIZED = 401
	HTTP_FORBIDDEN = 403
	HTTP_NOT_FOUND = 404
	HTTP_TIME_OUT = 405
	HTTP_INTERNAL_ERROR = 500
	HTTP_VERSION_NOT_SUPPORTED = 505

	ERROR_CODE_BAD_VERSION = AsErrorCode(505);
	ERROR_CDOE_BAD_AUTH = AsErrorCode(401);
	ERROR_CODE_WRONG_SERVER = AsErrorCode(301);
	ERROR_CDOE_BAD_REQUEST = AsErrorCode(400);
	ERROR_CDOE_TIME_OUT = AsErrorCode(HTTP_TIME_OUT);
	ERROR_CODE_UNAUTHROZID = AsErrorCode(HTTP_UNAUTHORIZED)
	ERROR_INTERNAL_ERROR = AsErrorCode(HTTP_INTERNAL_ERROR)

	EXT_BIN = ".bin"
	EXT_LOG = ".log"
	EXT_OBJ = ".obj"
	EXT_LZ4 = ".lz4"
	EXT_CZC = ".czc"
	//EXT_THUMBNAIL = ".tnl"
	THUMB_NAIL_SIZE = 128;
	META_PATH_SEPERATOR = "|"
	META_PATH_STATE_NORMAL = 0;
	META_PATH_STATE_INCOMPLETE = 1;
	META_PATH_STATE_OBSOLETE = 2;
	META_PATH_ID_SEPARATOR = "@"
	META_PATH_HASH_SEPARATOR = "#"
	DAT_SEPERATOR = "-"
	LOCALS_SEPARATOR1 = ","
	LOCALS_SEPARATOR2 = "-"

	REMOTE_TYPE_LOCAL_NFS = "NFS";

	REMOTE_TYPE_OFFICIAL    = "O";

	REMOTE_TYPE_SERVER    = "SVR";
	REMOTE_TYPE_SERVER_NAME    = "0";

	REMOTE_TYPE_S3    = "S3";
	REMOTE_TYPE_B2    = "B2";

	MASTER_KEY_FILE = "master.keys"
	ACCESS_KEY_FILE = "access.keys"

	AS_USER = "AS-UserID"
	AS_TIME = "AS-Time"
	AS_AUTH = "AS-Auth"
	AS_DEVICE = "AS-DeviceName"

	MSG_PREFIX = "MSG:"

	ATTR_REPO = "repo"
	ATTR_SHARE = "share"
	ATTR_THUMBNAIL = "tb"

	REPO_SHARE_STATE_ALL   = 0
	REPO_SHARE_STATE_OWNER = 1

	/* for folders shared from others */
	REPO_SHARE_STATE_SHARE = 2
	//REPO_SHARE_STATE_ALL = 3

	SUBSCRIBE = "subscribe"

	TASK_UPDATE_ROW    = 0
	TASK_CREATE_BIN    = 1
	TASK_WRITE_BIN     = 2
	TASK_APPEND_BIN    = 3
	TASK_DELETE_FILE   = 4
	TASK_ADD_FILE_NAME = 5
	TASK_UPDATE_LOCAL  = 6
	TASK_COPY_BIN   = 7
	TASK_IGNORE    = 100000

	//Non-Sync Tasks :

	TASK_RESET_ALL = 50
	//End of Non-Sync Tasks

	SIDE_SERVER_ONLY = 1
	SIDE_CLIENT_ONLY = -1

	LOGIN_KEY_TEXT = "key"
	LOGIN_SERVER_TEXT = "server"

	SERVER_MAIN_PORT = 65065
	LOCAL_HTML_PORT = "localhost:65066"

	CLIENTS_DAT_FILE = "clients.dat"

	DAT_KEY_PREFIX = "X"
)
const GB int64 = 1000000000
const TYPE_MASK uint32 = 0xFFF00000
const PERMISSION_MASK uint32 = 0x0000FFFF
const TYPE_PIPE uint32 = 0x20000000
const TYPE_DIRECTORY uint32 = 0x40000000
const TYPE_FILE uint32 = 0x80000000
const TYPE_DELETED uint32 = 0x00000000
const TYPE_DELETED_FILE uint32 = 0x00080000
const TYPE_DELETED_DIRECTORY uint32 = 0x00040000

const TYPE_REPOSITORY uint32 = 0xF0000000

const FILTER_NONE = 0
const FILTER_DIR_ONLY = 1
const FILTER_FILE_ONLY = 2
const FILTER_DELETED_ONLY = 3

/* operation Mode consts */
const MODE_UNKNOWN = 0

const MODE_MODIFIED_CONTENTS = 1

const MODE_MODIFIED_PERMISSIONS = 2

const MODE_NEW_FILE = 3

const MODE_NEW_DIRECTORY = 4

const MODE_DELETED_FILE = 5

const MODE_DELETED_DIRECTORY = 6

const MODE_RENAMED_FILE = 7

const MODE_RENAMED_DIRECTORY = 8

const MODE_REINSTATE_FILE = 9

const MODE_REINSTATE_DIRECTORY = 10

const MODE_MOVED_FILE = 11

const CONFLICT_SAME_INDEX = 1
const CONFLICT_NEW_INDEX = 2
const CONFLICT_REINSTATE_DIRECTORY = 3

const SEPARATOR string = "|"

const CONFLICT_NAME_PREFIX = "[(C)]"


/*
   ^ / ? < > \ : * | "  .(trailing)    Space(trailing)
    0 1 2 3 4 5 6 7 8 9  A              B

*/
var ESCAPE_CHARS = map[byte]byte{
	'0': '^',
	'1': '/',
	'2': '?',
	'3': '<',
	'4': '>',
	'5': '\\',
	'6': ':',
	'7': '*',
	'8': '|',
	'9': '"',
	'A': ' ',
	'B': '.',
}

var SPECIAL_CHARS map[byte]byte

var WIN_RESERVED_WORDS = map[string]bool{
	"com1": true,
	"com2": true,
	"com3": true,
	"com4": true,
	"com5": true,
	"com6": true,
	"com7": true,
	"com8": true,
	"com9": true,
	"lpt1": true,
	"lpt2": true,
	"lpt3": true,
	"lpt4": true,
	"lpt5": true,
	"lpt6": true,
	"lpt7": true,
	"lpt8": true,
	"lpt9": true,
	"con": true,
	"nul": true,
	"prn": true,
}


//var GetAppHome() string = GetAppHome()
var APP_TOP = GetAppRoot();
var UPDATE_DAT string = "/updateDat"
var UPLOAD_STAGING string = "uploadStaging"
var IS_MAIN_SERVER_SIDE = false;
var IS_OFFICIAL_MAIN_SERVER = false;

var gCurrentHome string;
var gAppRoot string;
var GNoResetAppHome bool = false;
func GetAppRoot()string{
	if(len(gAppRoot ) > 0){
		return gAppRoot;
	}
	usr, err := user.Current()
	if err != nil {
		Critical(err)
	}
	h := usr.HomeDir + "/.AnySync/"
	return h;
}

func SetAppRoot(r string){
	gAppRoot = r;
}
func SetAppHomeWithAbsolutePath(p string){
	gCurrentHome = p;
}

func GetAppHome() string {
	if(gCurrentHome != "") {return gCurrentHome;}
	usr, err := user.Current()
	if err != nil {
		Critical(err)
	}
	h := usr.HomeDir + "/.AnySync"
	if(!FileExists(h)) {Mkdir(h);}
	if client, err := ReadString(h + "/" + "current"); err == nil {
		client = strings.TrimSpace(client);
		gCurrentHome = h + "/" + client + "/"
		//Debug("Current is ", client)
		return gCurrentHome;
	}else{
		return "";
		//return h + "/0/";
	}
}

func SetAppHome(userID string){
	if(GNoResetAppHome){
		return;
	}
	root:=GetAppRoot();
	WriteString(root + "current", userID);
	gCurrentHome = "" //reset it
	GetAppHome();
}
func CurrentFileExists()bool{
	root:=GetAppRoot();
	return FileExists(root + "current");
}
func GetFolder(name string)string{
	if(gCurrentHome == ""){ return "";}
	return gCurrentHome + name + "/";
}

func GetTasksFolder()string{
	return GetFolder("tasks");
}
func GetUpdateDatTasksFolder()string{
	if(gCurrentHome == ""){ return "";}
	return GetFolder("tasks") + UPDATE_DAT;
}
func GetResetAllTasksFolder()string{
	if(gCurrentHome == ""){ return "";}
	return GetFolder("tasks") + "resetAll";
}

func GetPacksFolder() string{
	return GetFolder("packs")
}

func GetLogsFolder() string{
	return GetFolder("logs")
}

func GetDataFolder() string{
	return GetFolder("data")
}

func GetTopTreeFolder() string{
	return GetFolder("tree")
}

func GetTopNamesFolder() string{
	return GetFolder("names")
}

func GetTopObjectsFolder() string{
	return GetFolder("objects")
}
func GetTopShareFolder() string{
	return GetFolder("share")
}
func GetTopRestoreFolder() string{
	return GetFolder("restore")
}
func GetTopTmpFolder() string{
	return GetFolder("tmp")
}
func GetStagingFolder() string{
	if(gCurrentHome == ""){ return "";}
	return GetFolder("tmp") + "staging/";
}
