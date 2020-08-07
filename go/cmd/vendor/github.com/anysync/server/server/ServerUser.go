// Copyright (c) 2020, Yanbin (Henry) Zheng <ybzheng@gmail.com>
// All rights reserved.
//
// Use of this source code is governed by a AGPLv3 license that can be
// found in the LICENSE file.

package server

import (
	

	"crypto/rand"
	"encoding/hex"
	"fmt"
	"github.com/asdine/storm"
	"github.com/asdine/storm/codec/protobuf"
	"golang.org/x/crypto/nacl/box"
	"io"
	"path/filepath"
	"strings"
	"sync"
	"time"
	utils "github.com/anysync/server/utils"
)
var MASTER_ENC_KEY_INITED bool
var MASTER_ENC_KEY_SERVER [32]byte
var MASTER_AUTH_KEY_INITED bool
var MASTER_AUTH_KEY_SERVER [32]byte
var UserDB *storm.DB

var NextUserID int;
func OpenUserDB(dbFile string) {
	if UserDB != nil {
		return
	}
	if(!utils.FileExists(dbFile)) {
		folder := filepath.Dir(dbFile);
		fmt.Println("DB dir is ", folder)
		_ = utils.MkdirAll(folder);
	}

	db, err := storm.Open(dbFile, storm.Codec(protobuf.Codec))

	//db, err := bolt.Open(dbFile, 0600, nil)
	if err != nil {
		utils.Critical("Cannot open user db file : ", dbFile)
		return
	}
	utils.Info("Database initialized at ", dbFile)
	UserDB = db

	user := DbUserAccount{}
	c, _ := db.Count(&user)
	NextUserID = c + FIRST_ID ;
	

}

func init() {
}




func GetMainServerAuthKey() [32]byte {
	if !MASTER_AUTH_KEY_INITED {
		config := utils.LoadServerConfig();
		auth := strings.TrimSpace(config.Auth)
		if len(auth) != 64 {
			r := make([]byte, 32)
			if _, err := io.ReadFull(rand.Reader, r); err != nil {
				panic(err.Error())
			}
			config.Auth = hex.EncodeToString(r)
			utils.SaveServerConfigFile(config, utils.GetServerConfigFile())
			copy(MASTER_AUTH_KEY_SERVER[:], r)
		}else{
			copy(MASTER_AUTH_KEY_SERVER[:], utils.FromHex(auth))
		}
 		MASTER_AUTH_KEY_INITED = true
	}
	return MASTER_AUTH_KEY_SERVER
}

var MAIN_SERVER_PUB_KEY *[32]byte
var MAIN_SERVER_PRIV_KEY *[32]byte

func GetMainServerRsaKeys() (*[32]byte, *[32]byte) {
	if MAIN_SERVER_PRIV_KEY == nil {
		myPublicKey, myPrivateKey, _ := box.GenerateKey(rand.Reader)
		MAIN_SERVER_PUB_KEY = myPublicKey
		MAIN_SERVER_PRIV_KEY = myPrivateKey
	}
	return MAIN_SERVER_PRIV_KEY, MAIN_SERVER_PUB_KEY
}

func getAuthKey(user *utils.UserAccount) []byte {
	if user.RealAuthKey != nil {
		return user.RealAuthKey
	}
	bs, _ := utils.Decrypt(user.AuthKey, &MASTER_ENC_KEY_SERVER)
	user.RealAuthKey = bs
	return bs
}



func IsTestAccount(email string)bool{



	return false

}

func AddUserAccount(email, pubKey, name, ip, remoteNameCode string) (*utils.UserAccount, error) {
	utils.Debug("Enter UpdateUserInDb Account: ", email)
	defer utils.Debug("Leave AddUserAccount: ", email)
	user := new(utils.UserAccount)
	user.MaxID++;
	user.Email = email
	user.Name = name
	r, _ := utils.GenerateRandomBytes(32)
	user.AuthKey, _ = utils.Encrypt(r, &MASTER_ENC_KEY_SERVER)
	user.AccessToken, _ = utils.GenerateRandomBytes(32)
	user.PubKey = utils.FromHex(pubKey) // []byte(pubKey); //rsa pub key actually.
	user.Server = utils.LoadAppParams().Server


	user.Bucket = utils.LoadAppParams().GetStorageBucket(remoteNameCode)
	n := time.Now()
	user.LastLogin = uint32(n.Unix());
	user.LastIP = ip;
	n = n.AddDate(0, 0, 31)
	user.Expiry = uint32(n.Unix())
	err := UpdateUserAtRootServer(user, true)
	if err != nil {
		return nil, err
	} else {
		return user, nil
	}
}

func AuthenticateUserAccount(user *utils.UserAccount, receivedPassword string, t uint32) bool {
	if user == nil {
		return false
	}
	userID := fmt.Sprintf("%d", user.ID)
	auth := utils.CreateSignatureString(user.AccessToken, userID, t)
	utils.Debug("userID: ", userID, "; Time: ", t, "; Token: ", fmt.Sprintf("%x", user.AccessToken))
	if auth == receivedPassword {
		return true
	} else {
		utils.Debug("passwords do not match.")
		return false
	}
}

func UpdateUserAtRootServer(user *utils.UserAccount, isNew bool) error {
	


	
	UpdateUserInDb(user, isNew) //update local data
	
	return nil
}




func GetUserAccountByID(userID int) (*utils.UserAccount, utils.AsErrorCode) {
	return GetUserAccountBy(fmt.Sprintf("%d", userID), true)
}

func GetUserAccount(user string) (*utils.UserAccount, utils.AsErrorCode) {
	return GetUserAccountBy(user, false)
}

func GetUserAccountBy(user string, byID bool) (*utils.UserAccount, utils.AsErrorCode) {


		var u *utils.UserAccount
		if byID {
			u = doGetUserAccountByID(utils.ToInt(user)) //update local data
		} else {
			u = doGetUserAccount(user)
		}
		utils.Debug("Same db server and server. userID is", user)
		return u, 0


}

func DeleteUserAccount(userID int)error{
	u := DbUserAccount{}
	u.ID = userID
	return UserDB.DeleteStruct(&u)
}

func doGetUserAccount(username string) *utils.UserAccount {
	var u DbUserAccount
	if err := UserDB.One("Email", username, &u); err == nil {
		if u.Expired() {
			return nil
		}
		user := ToUserAccount(&u)
		return user
	} else {
		utils.Debug("Username not found: ", username)
		return nil
	}

}

func doGetUserAccountByID(userID int) *utils.UserAccount {
	var u DbUserAccount
	if err := UserDB.One("ID", userID, &u); err == nil {
		if u.Expired() {
			return nil
		}
		user := ToUserAccount(&u)
		return user
	} else {
		utils.Debugf("User not found for ID: %d", userID)
		return nil
	}
}

var updateUserDbMutext = &sync.Mutex{}

func UpdateUserInDb(user *utils.UserAccount, isNew bool) error {
	updateUserDbMutext.Lock();
	defer updateUserDbMutext.Unlock();
	if(IsTestAccount(user.Email)){


	}else {
		if(isNew){
			//double check if user ID conflicts
			if doGetUserAccountByID(int(NextUserID)) != nil {
				//already exists
				utils.Info("user id already exists:", NextUserID)
				NextUserID++;
			}
			user.ID = int32(NextUserID);
			NextUserID++;
			user.Prefix = GetOfficialServerUserPrefix(fmt.Sprintf("%d", user.ID))
		}
	}
	u := ToDbAccount(user)
	u.LastLogin = uint32(time.Now().Unix())
	if isNew {
		u.Register = uint32(time.Now().Unix())
	}
	err := UserDB.Save(u)
	if err != nil {
		utils.Debugf("Error is %v", err)
		return err
	} else {
		utils.Debug("UpdateUserInDb. Account id: ", user.ID, "; AccountType:", u.AccountType, "; Quota:", u.Quota, "; expiry:", time.Unix(int64(u.Expiry), 0) ,  "; prefix:", u.Prefix)
		return nil
	}
}





/**
User account object for boltdb
AccountType: 0 - Trial   50: 50GB 200: 200GB
Quota: storage quota in GB.
*/
type DbUserAccount struct {
	ID           int  `storm:"id"`//primary key   `storm:"id,increment=1170367"` // primary key, start from 1170367
	AccountType  int
	AccountRole  int
	Organization string `storm:"index"`  // this field will be indexed
	Group        string `storm:"index"`  // this field will be indexed
	Email        string `storm:"unique"` // this field will be indexed with a unique constraint
	Name         string // this field will not be indexed
	AccessToken  []byte
	Devices      map[string]string
	Register     uint32
	MaxID       uint32
	LastLogin    uint32
	LastIP      string
	Expiry       uint32
	AuthKey      []byte
	Server       string //Server IP/hostname
	PubKey      []byte
	Quota       uint32
	Phone       string
	OrderID      string
	//The prefix is the part after bucket, for 1001:AnySync1/027379fc9abf45c279b7a2710d830f110a26a9ad3c10316bbe6d4e09/objects/9b/fc/82/48039fc4922bd0bf63668b86d8eeeff3259b00bad97ddf46f3.obj,
	//the prefix is 027379fc9abf45c279b7a2710d830f110a26a9ad3c10316bbe6d4e09
	Prefix string
	Bucket string
	realAuthKey []byte
}

func (acct DbUserAccount)Expired() bool{
	if acct.Expiry == 0 {
		return false;
	}
	now := uint32(time.Now().Unix());
	if   now > acct.Expiry  {
		return true;
	}
	return false;
}

func ToDbAccount(user * utils.UserAccount) * DbUserAccount{
	u := new(DbUserAccount)
	u.Name = user.Name
	u.ID = int(user.ID)
	u.Server = user.Server
	u.Email = user.Email
	u.AuthKey = user.AuthKey
	u.AccountType = int(user.AccountType)
	u.AccountRole = int(user.AccountRole)
	u.AccessToken = user.AccessToken
	u.PubKey = user.PubKey
	u.Group = user.Group
	u.Organization = user.Organization
	u.MaxID = uint32(user.MaxID)
	u.LastIP = user.LastIP
	u.LastLogin = user.LastLogin
	u.Register = user.Register;
	u.Quota = user.Quota;
	u.Phone = user.Phone;
	u.Expiry = user.Expiry;
	u.Prefix = user.Prefix;
	u.Bucket = user.Bucket;
	u.OrderID = user.OrderID;
	return u;
}
func ToUserAccount(user * DbUserAccount) * utils.UserAccount{
	u := new(utils.UserAccount)
	u.Name = user.Name
	u.ID = int32(user.ID);
	u.Server = user.Server
	u.Email = user.Email
	u.AuthKey = user.AuthKey
	u.AccountType = int32(user.AccountType)
	u.Prefix = user.Prefix;
	u.AccountRole = int32(user.AccountRole)
	u.AccessToken = user.AccessToken
	u.PubKey = user.PubKey
	u.Group = user.Group
	u.Organization = user.Organization
	u.MaxID = int32(user.MaxID);
	u.LastIP = user.LastIP;
	u.LastLogin = user.LastLogin
	u.Register = user.Register;
	u.Quota = user.Quota;
	u.Phone = user.Phone;
	u.Expiry = user.Expiry;
	u.OrderID = user.OrderID;
	u.Bucket = user.Bucket;
	return u;
}
