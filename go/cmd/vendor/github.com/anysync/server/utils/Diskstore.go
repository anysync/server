// Copyright (c) 2020, Yanbin (Henry) Zheng <ybzheng@gmail.com>
// All rights reserved.
//
// Use of this source code is governed by a AGPLv3 license that can be
// found in the LICENSE file.

package utils

import (
	"database/sql"
	"fmt"
	_ "github.com/mattn/go-sqlite3"
	"path/filepath"
)

var namesdb *sql.DB;

func NewDb(dbFile string) *sql.DB{
	exists := FileExists(dbFile)
	Info("To open db file:", dbFile, "; exists? ", exists)
	if(!exists){
		dir := filepath.Dir(dbFile)
		if !FileExists(dir) {
			_ = MkdirAll(dir)
		}
	}
	db, err := sql.Open("sqlite3", dbFile)//, 0600, nil)
	if err != nil {
		Error(err, "cannot open " + dbFile)
		return nil;
	}

	if(!exists){
		//db.Exec("PRAGMA journal_mode=WAL;")
		_, err = db.Exec("CREATE TABLE IF NOT EXISTS kv (key TEXT PRIMARY KEY, value BLOB)")
		if err != nil {
			Error("Cannot create table kv for file:", dbFile, "; Error is", err)
		}
	}

	if(db == nil){
		Error("Cannot open db: ", dbFile)
	}
	return db;
}

func CloseDb(db * sql.DB){
	if db != nil {
		_ = db.Close()
	}
}
func clientInit(){
	//if(clientInited){return};
	//clientInited = true;
	if IS_MAIN_SERVER_SIDE {
		return;
	}
	if(GetAppHome() == ""){
		return;//not ready yet
	}
	if(namesdb != nil){
		return;
	}
	//fmt.Println("AppHome:", GetAppHome())
	namesdb = NewDb(GetAppHome() + "/names/data.db")
}

func ResetNamesDb(){
	if(namesdb == nil) {return;}
	namesdb.Close();
	namesdb = nil;
	//clientInited = false;
}

func DbSetValue(key string, value []byte) error{
	//db.Write(key, value)
	if(namesdb == nil) {clientInit();}
	return SetValue(namesdb, key, value)
	//namesdb.Update(func(tx *bolt.Tx) error {
	//	b := tx.Bucket([]byte("Client"))
	//	err := b.Put([]byte(key), value)
	//	return err
	//})
}

func SetValue(db * sql.DB, key string, value []byte) error{
	sql := "REPLACE INTO kv (key, value) VALUES (?,?)"
	stat, _ := db.Prepare(sql)
	_, err := stat.Exec(key, string(value));
	stat.Close()
	if(err!= nil){
		Debug("Cannot set value. err:", err)
	}
	return err
}
//func SetDbValue(db * sql.DB, key string, value []byte){
//	//db.Write(key, value)
//	if(!clientInited) {clientInit();}
//	sql := "REPLACE INTO kv (key, value) VALUES (?,?)"
//	stat, _ := db.Prepare(sql)
//	stat.Exec(key, string(value));
//
//
//	//db.Update(func(tx *bolt.Tx) error {
//	//	b := tx.Bucket([]byte("Client"))
//	//	err := b.Put([]byte(key), value)
//	//	return err
//	//})
//}


func NamesDbSetStringValue(key string, value string){
	if(namesdb == nil) {clientInit();}
	sql := "REPLACE INTO kv (key, value) VALUES (?,?)"
	stat, _ := namesdb.Prepare(sql)
	defer stat.Close();
	_, err := stat.Exec(key, value);
	if(err!= nil){
		Debug("Cannot set value. err:", err)
	}

	//namesdb.Update(func(tx *bolt.Tx) error {
	//	b := tx.Bucket([]byte("Client"))
	//	if(b == nil){
	//		b, _ = tx.CreateBucket([]byte("Client"))
	//	}
	//	err := b.Put([]byte(key), []byte(value))
	//	return err
	//})
}

func DbGetValue(key string) ([]byte, bool){

	if namesdb == nil{
		clientInit()
	}
	return GetValue(namesdb, key)
	//var ret []byte;
	//found := false;
	//namesdb.View(func(tx *bolt.Tx) error {
	//	b := tx.Bucket([]byte("Client"))
	//	if(b == nil){
	//		return nil;
	//	}
	//
	//	r := b.Get([]byte(key))
	//	if(r == nil){
	//		return nil;
	//	}
	//	ret = make([]byte, len(r))
	//	copy(ret, r)
	//	found = true;
	//	return nil
	//})
	//return ret, found
}
func GetValue(db * sql.DB, key string ) ([]byte, bool) {

	sql := "SELECT value FROM kv WHERE key = ?";
	var val string;
	if db == nil {
		Error("Null db. key:", key)
	}
	row, _ := db.Query(sql, key)
	if row == nil {
		return nil, false;
	}
	defer row.Close();
	for row.Next() {
		row.Scan(&val)
		return []byte (val), true;
	}
	return nil, false;
}
//func GetDbValue(db * sql.DB, key string) ([]byte, bool){
//	if(!clientInited) {clientInit();}
//	var ret []byte;
//	found := false;
//	db.View(func(tx *bolt.Tx) error {
//		b := tx.Bucket([]byte("Client"))
//		if(b == nil){
//			return nil;
//		}
//
//		r := b.Get([]byte(key))
//		if(r == nil){
//			return nil;
//		}
//		ret = make([]byte, len(r))
//		copy(ret, r)
//		found = true;
//		return nil
//	})
//	return ret, found
//}

func ObjectsDbSetStateValue( key string, v byte){
	if(namesdb == nil) {clientInit();}
	if val, b := DbGetValue(key);  b{
		val[0] = v
		DbSetValue(key, val)
	}
}

func DbGetStringValue(key string, toDecrypt bool) (string, bool) {
	val, found := DbGetValue(key);
	if(found && toDecrypt) {
		s := GetDisplayFileName(string(val));
		return s, found;
	}
	if(!found || val == nil){
		return "", false;
	}
	return string(val), found;
}

func DbGetStringValues(keys []string, toDecrypt bool )  map[string][]byte {
	return GetStringValues( keys, toDecrypt)
}

func GetStringValues(  keys []string, toDecrypt bool )  map[string][]byte{
	if(namesdb == nil) {clientInit();}
	buf := ""
	n := len(keys)
	for i := 0; i < n; i++ {
		/*
		  buf.append("'"). append(keys.get(i)).append("'");
		            if(i != n - 1)
		            {
		                buf.append(",");
		            }
		 */
		buf += "'"  + keys[i] + "'"
		if i != n -1 {
			buf += ","
		}
	}
	sql := "SELECT key, value FROM kv WHERE key in (" + buf  + ")"
	var key, val string;
	row, _ := namesdb.Query(sql)
	ret := make (map[string][]byte)
	if row == nil {
		return ret;
	}
	defer row.Close();
	for row.Next() {
		row.Scan(&key, &val)
		if(toDecrypt){
			val = GetDisplayFileName(string(val));
		}
		ret[key] = []byte (val);
	}
	return ret;
}

func DbSetStringValues( kvs map[string][]byte)error{
	if(namesdb == nil) {clientInit();}
	return SetStringValues(namesdb, kvs)
	//n := len(kvs)
	//valueStrings := make([]string, 0, n)
	//valueArgs := make([]interface{}, 0, n * 2)
	//for k, v := range kvs {
	//	valueStrings = append(valueStrings, "(?,?)")
	//	valueArgs = append(valueArgs, k)
	//	valueArgs = append(valueArgs, v)
	//}
	//namesdb.Exec("PRAGMA journal_mode=WAL;");
	//stmt := fmt.Sprintf("INSERT INTO kv (key, value) VALUES %s",
	//	strings.Join(valueStrings, ","))
	//namesdb.Exec(stmt, valueArgs...)

	//namesdb.Batch(func(tx *bolt.Tx) error {
	//	b := tx.Bucket([]byte("Client"))
	//	if(b == nil){
	//		b, _ = tx.CreateBucket([]byte("Client"))
	//	}
	//	for key, value := range kvs {
	//		b.Put([]byte(key),  value)
	//	}
	//	return nil
	//})

}
func SetStringValues( db * sql.DB, kvs map[string][]byte) error{
	//n := len(kvs)
	//valueStrings := make([]string, 0, n)
	//valueArgs := make([]interface{}, 0, n * 2)
	//for k, v := range kvs {
	//	valueStrings = append(valueStrings, "(?,?)")
	//	valueArgs = append(valueArgs, k)
	//	valueArgs = append(valueArgs, v)
	//}
	////db.Exec("PRAGMA journal_mode=WAL;");
	//stmt := fmt.Sprintf("REPLACE INTO kv (key, value) VALUES %s",
	//	strings.Join(valueStrings, ","))
	//_, err := db.Exec(stmt, valueArgs...)
	//if err != nil {
	//	Warn("SetStringValues error:", err)
	//}


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

	//namesdb.Batch(func(tx *bolt.Tx) error {
	//	b := tx.Bucket([]byte("Client"))
	//	if(b == nil){
	//		b, _ = tx.CreateBucket([]byte("Client"))
	//	}
	//	for key, value := range kvs {
	//		b.Put([]byte(key),  value)
	//	}
	//	return nil
	//})

}

func DeleteTasks(db * sql.DB, keys[]string) error {
	if (keys == nil || len(keys) == 0) {
		return nil;
	}
	sql := "SELECT count(key) FROM kv "
	var key int;
	row, _ := db.Query(sql)
	if row == nil {
		return nil;
	}
	for row.Next() {
		row.Scan(&key)
		break;
	}
	row.Close();
	if key == len(keys) {
		sql = "delete from kv"
		_, e := db.Exec(sql)
		return e;
	}

	return DeleteKeys(db, keys)
}

func DeleteKeys(db* sql.DB, keys[]string)error{

	tx,err:=db.Begin();
	for _, k := range keys{
		_, err = tx.Exec("delete from kv where key=?", k)
		if err != nil {
			tx.Rollback()
			return err
		}

	}
	err = tx.Commit()
	return err;


	//text := "";
	//for _, k := range keys{
	//	text += "'" + k + "',"
	//}
	//text = text[0:len(text) - 1]
	////fmt.Println("text:", text)
	//stmt := fmt.Sprintf("delete from kv where key in ( %s )", text)
	//_, err := db.Exec(stmt)
	//if err != nil {
	//	Warn("Delete error:", err)
	//}
	//return err;
}

//return true if change occurs
func ObjectsDbSetStateValueTo(hash string, v byte) (*FileMeta, bool) {
	key := DAT_KEY_PREFIX + hash;
	if value, found := DbGetValue(key); found{
		var meta * FileMeta;

		if(len(value) > 9) {
			val := value[9:]
			meta = BytesToFileMeta(val)
		}
		if(value[0] == v){
			return meta, false;
		}
		value[0] = v;
		DbSetValue(key, value)
		return meta, true;
	}
	return nil, false;
}


func UpdateDatFile(hash string, contents []byte, user string){
	key := DAT_KEY_PREFIX + hash
	var val []byte;
	val = append(val, byte(1))
	fileMeta := BytesToFileMeta(contents)
	size := Int64ToBytes(fileMeta.C)
	val = append(val, size...)
	val = append(val, contents...)
	if(user == "") {
		DbSetValue(key, val)
	}else{
		ServerObjectDbSetValue(user, key, val)
	}
}

//The .dat file entry format:
//for key: DAT_KEY_PREFIX + hash
//for value: first byte is the status, 1 means valid, 0 means invalid.
//Next 8 bytes are the size of cloud storage.
//Starting from 9th byte, it's the byte array of FileMeta object
func AddDatFile(ms map[string]map[string][]byte, hash string, contents []byte, user string) {
	key := DAT_KEY_PREFIX + hash
	var val []byte;
	val = append(val, byte(1)) //entry status byte, 1 means valid
	fileMeta := BytesToFileMeta(contents)
	size := Int64ToBytes(fileMeta.C)
	val = append(val, size...)
	val = append(val, contents...)
	if m,ok := ms[user] ; ok {
		m[key] = val;
	}else {
		nm := make(map[string][]byte)
		nm[key] = []byte(val);
		ms[user] = nm;
	}
}

func DatFileExists(hash string)bool{
	key := DAT_KEY_PREFIX + hash
	val, found := DbGetValue(key)
	if(found && len(val)>0){
		if(val[0] == 1){  //1 means valid
			return true;
		}else{
			return false;
		}

	}
	return found
}

func SaveDatFiles(ms map[string]map[string][]byte) {
	for user, m := range ms {
		if(user == ""){
			DbSetStringValues(m)
		}else{
			Debug("To call ServerDbSetStringValues")
			ServerDbSetStringValues(user, m, false)
			Debug("ServerDbSetStringValues returned.")
		}
	}
}

func GetDatObject(hash string) * FileMeta {
	meta, _ := GetDatObjectAndContent(hash);
	return meta;
}
func GetDatObjectValue(val[]byte)   (* FileMeta,[]byte){
	if(len(val)<=9){
		return nil, val;
	}
	if(val[0] != 1){
		return nil, val;
	}
	v := val[9:]
	fileMeta := BytesToFileMeta(v)
	return fileMeta, v;
}

func GetDatObjectAndContent(hash string)  (* FileMeta,[]byte) {
	key := DAT_KEY_PREFIX + hash
	val, found := DbGetValue(key)
	if found  && len(val) > 0 && val[0] == 1 {
		return GetDatObjectValue(val);
	}else{
		return nil, nil;
	}
}

func ObjectsDbSetStateValuesTo(nv byte){
	if namesdb == nil {
		clientInit();
	}

	sql := "SELECT key, value FROM kv WHERE key like '" + DAT_KEY_PREFIX + "%'";
	var key, val string;
	row, _ := namesdb.Query(sql)
	if row == nil {
		return
	}

	kvs := make(map[string][]byte)
	defer row.Close();
	for row.Next() {
		row.Scan(&key, &val)
		bs := []byte(val)
		if(len(bs) > 0){
			bs[0] = nv
		}
		kvs[key] = bs;
	}
	SetStringValues(namesdb, kvs)

	//namesdb.Update(func(tx *bolt.Tx) error {
	//	// Assume bucket exists and has keys
	//	b := tx.Bucket([]byte("Client"))
	//	if(b == nil){
	//		return nil
	//	}
	//	c := b.Cursor()
	//
	//	prefix := []byte(DAT_KEY_PREFIX)
	//	for k, v := c.Seek(prefix); k != nil && v != nil && bytes.HasPrefix(k, prefix); k, v = c.Next() {
	//		r := make([]byte, len(v))
	//		copy(r, v)
	//		r[0] = nv;
	//		b.Put(k, v)
	//	}
	//
	//	return nil
	//})

}

func DbIterate(db * sql.DB, pre string, f func([]byte, []byte) bool){
	sql := "SELECT key, value FROM kv order by rowid";
	if pre != ""{
		sql = "SELECT key, value FROM kv where key like '" + pre + "%'  order by rowid";
	}
	var key, val string;
	row, _ := db.Query(sql)
	if row == nil {
		return ;
	}
	defer row.Close();
	for row.Next(){
		row.Scan(&key, &val)
		if !f([]byte(key), []byte(val)) {
			break
		}
	}

	//db.View(func(tx *bolt.Tx) error {
	//	// Assume bucket exists and has keys
	//	b := tx.Bucket([]byte("Client"))
	//	if(b == nil){
	//		return nil
	//	}
	//	c := b.Cursor()
	//
	//	prefix := []byte(pre)
	//	for k, v := c.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, v = c.Next() {
	//		f(k, v)
	//	}
	//
	//	return nil
	//})
}

func CountTotalSize(addUnit bool) string{
	if(namesdb == nil) {clientInit();}

	var total  int64 = 0;
	DbIterate(namesdb, DAT_KEY_PREFIX, func(key []byte, val []byte) bool {
		if(len (val) <=9 ){
			return true
		}
		if(val[0] != 1){
			return true
		}

		v := val[1:9]
		s := BytesToInt64(v)
		total += s
		return true
	})
	if(addUnit) {
		return ToUnit(total);
	}else{
		return fmt.Sprintf("%d", total);
	}
}

//@param f: return true to continue loop; false to get out loop.
func IterateDatObject2(db *sql.DB, f func([]byte, *FileMeta) bool){
	//if(!clientInited) {clientInit();}
	DbIterate(db, DAT_KEY_PREFIX, func(k []byte, v []byte) bool {
		fileMeta,_ := GetDatObjectValue(v);

		if !f(k, fileMeta) {
			return false;
		}
		return true
	});

	//db.View(func(tx *bolt.Tx) error {
	//	// Assume bucket exists and has keys
	//	b := tx.Bucket([]byte("Client"))
	//	if b == nil {
	//		return nil
	//	}
	//	c := b.Cursor()
	//
	//	prefix := []byte(DAT_KEY_PREFIX)
	//	for k, v := c.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, v = c.Next() {
	//
	//		fileMeta,_ := GetDatObjectValue(v);
	//		if !f(k, fileMeta) {
	//			break;
	//		}
	//
	//	}
	//
	//	return nil
	//})
}

//@param f: return true to continue loop; false to get out loop.
func IterateDatObject(f func([]byte, *FileMeta) bool){
	if(namesdb == nil) {clientInit();}
	DbIterate(namesdb, DAT_KEY_PREFIX, func(k []byte, v []byte) bool {
		fileMeta,_ := GetDatObjectValue(v);
		if !f(k, fileMeta) {
			return false;
		}

		return true
	});


	//namesdb.View(func(tx *bolt.Tx) error {
	//	// Assume bucket exists and has keys
	//	b := tx.Bucket([]byte("Client"))
	//	if b == nil {
	//		return nil
	//	}
	//	c := b.Cursor()
	//
	//	prefix := []byte(DAT_KEY_PREFIX)
	//	for k, v := c.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, v = c.Next() {
	//
	//		fileMeta,_ := GetDatObjectValue(v);
	//		if !f(k, fileMeta) {
	//			break;
	//		}
	//
	//	}
	//
	//	return nil
	//})

}

