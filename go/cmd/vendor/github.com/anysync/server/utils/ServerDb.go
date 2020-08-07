// Copyright (c) 2020, Yanbin (Henry) Zheng <ybzheng@gmail.com>
// All rights reserved.
//
// Use of this source code is governed by a AGPLv3 license that can be
// found in the LICENSE file.
package utils

import (
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/golang/protobuf/proto"
	"os"
	"strings"
)

func ServerDbGetStringValue(user, key string) (string, bool) {
	bs, b := ServerDbGetValue(user, key)
	return string(bs), b
}

func ServerDbGetValue(user, key string) ([]byte, bool) {
	serverNamesDbMutex.Lock(user)
	defer serverNamesDbMutex.Unlock(user)
	serverDb := NewDb(getServerUserDbFile(user))
	if serverDb == nil {
		return nil, false;
	}
	defer serverDb.Close()

	sql := "SELECT value FROM kv WHERE key = ?";
	var val string;

	row, _ := serverDb.Query(sql, key)
	if row == nil {
		return nil, false;
	}
	defer row.Close()
	for row.Next(){
		row.Scan(&val)
		return []byte (val), true;
	}
	return nil, false;
}

func ServerNamesDbSetStringValue(user, key, value string) error{
	serverNamesDbMutex.Lock(user)
	defer serverNamesDbMutex.Unlock(user)
	serverDb := NewDb(getServerUserDbFile(user))
	if serverDb == nil  {
		return errors.New("Cannot open db:" + getServerUserDbFile(user))
	}
	defer serverDb.Close()

	sql := "REPLACE INTO kv (key, value) VALUES (?,?)"
	stat, _ := serverDb.Prepare(sql)
	_, err := stat.Exec(key, string(value));
	stat.Close()
	return err;

}

func ServerNamesDbSetStringValues(user string, kvs map[string][]byte) error {
	return ServerDbSetStringValues(user, kvs, true)
}

func ServerObjectDbSetValue(user, key string, value []byte) error {
	serverNamesDbMutex.Lock(user)
	defer serverNamesDbMutex.Unlock(user)

	serverDb := NewDb(getServerUserDbFile(user))
	if serverDb == nil {
		return errors.New("Cannot open db: " + getServerUserDbFile(user))
	}
	defer serverDb.Close()

	sql := "REPLACE INTO kv (key, value) VALUES (?,?)"
	stat, _ := serverDb.Prepare(sql)
	_, err := stat.Exec(key, string(value))
	stat.Close()
	return err;
}

var serverNamesDbMutex = NewKmutext()
func ServerDbSetStringValues(user string, kvs map[string][]byte, lock bool) error{
	Debug("Enter ServerDbSetStringValues, kvs.len:", len(kvs), "; user:", user, "; to lock:", lock)
	defer Debug("Leave ServerDbSetStringValues, kvs.len:", len(kvs))
	if lock {
		serverNamesDbMutex.Lock(user)
		defer serverNamesDbMutex.Unlock(user)
	}
	db := NewDb(getServerUserDbFile(user))
	//Debug("Open serverdb for user:", user, "; db is null? ", (serverDb == nil))
	if db == nil {
		return errors.New("cannot open db:" + getServerUserDbFile(user))
	}
	defer db.Close()


	tx,err:=db.Begin();
	for k, v := range kvs {
		_, err = tx.Exec("REPLACE INTO kv VALUES (?, ?)", k, v)
		if err != nil {
			tx.Rollback()
			return err
		}

	}
	err = tx.Commit()
	return err;

}

func ServerObjectsDbIterate(userID string, f func([]byte, []byte) bool){
	serverNamesDbMutex.Lock(userID)
	defer serverNamesDbMutex.Unlock(userID)
	serverDb := NewDb(getServerUserDbFile(userID))
	if serverDb == nil {
		return
	}
	defer serverDb.Close()
	DbIterate(serverDb, DAT_KEY_PREFIX, f)
}

func getServerUserDbFile(user string)string{
	uid := ToInt(user);
	dir := "names"
	dbFile := fmt.Sprintf("%s/users/%s/%s/", ServerRoot,  IntToPath(uid), dir)
	if !FileExists(dbFile) {
		MkdirAll(dbFile)
	}
	dbFile +=  "data.db"
	return dbFile;
}

func GetServerDatObjectAndContent(userID, hash string)  (* FileMeta,[]byte) {
	key := DAT_KEY_PREFIX + hash
	val, found := ServerDbGetValue(userID, key)
	if (found && len(val) > 9) {
		v := val[9:]
		fileMeta := BytesToFileMeta(v)
		return fileMeta, v;
	}else{
		return nil, nil;
	}
}

var ServerRoot string;
func GetRootOnServer() string {
	if len(ServerRoot) == 0{
		fmt.Fprintln(os.Stderr, "Error. Empty server root.")
		os.Exit(1)
	}
	return ServerRoot;
}

func GetUserRootOnServer(userID string) string {
	if strings.HasSuffix(userID, "/") {
		Error("userID is not numeric: ", userID)
	}

	root := GetRootOnServer()
	return root + "users/" + IntStringToPath(userID)
}

func GetUserRootOnServerByID(userID int32) string {
	root := GetRootOnServer()
	return root + "users/" + IntToPath(int(userID))
}

func GetShareFolderByRepoHash(repoTreeFolder, repoHash string) *ShareFolder {
	return getShareFolderByRepoHash(repoTreeFolder, repoHash, "", false)
}

func GetShareFolderByRepoHashOnServer(user, repoTreeFolder, repoHash string) *ShareFolder {
	return getShareFolderByRepoHash(repoTreeFolder, repoHash, user, true)
}

func getShareFolderByRepoHash(repoTreeFolder, repoHash, user string, serverSide bool) *ShareFolder {
	base := repoTreeFolder + HashToPath(SHARED_HASH)
	binFile := base + ".bin"
	//Debug("binFile: ", binFile)
	if !FileExists(binFile) {
		Debug("binFile doesn't exist: ", binFile)
		return nil
	}
	rows := ReadBinAll(binFile, false)
	if len(rows) == 0 {
		Debug("rows.size is 0")
		return nil
	}
	for i, row := range rows {
		if i == 0 || IsFileModeDeleted(row.FileMode) {
			continue
		}
		key := CreateXattribKey(SHARED_HASH, uint32(row.Index))
		var found bool
		var xa string
		if serverSide {
			xa, found = ServerDbGetStringValue(user, key)
		} else {
			xa, found = DbGetStringValue(key, false)
		}
		if found {
			fattr := FileAttribs{}
			fattr.Attribs = make(map[string][]byte)
			if proto.Unmarshal([]byte(xa), &fattr) == nil {
				if shareFolder := GetShareFromBytes(fattr.Attribs[ATTR_SHARE]); shareFolder != nil {
					if shareFolder.Hash == repoHash {
						return shareFolder
					}
				}
			} else {
				Debug("Unmarshall return nil: ", hex.EncodeToString([]byte(xa)))
			}
		}
	}
	return nil
}
