// Copyright (c) 2020, Yanbin (Henry) Zheng <ybzheng@gmail.com>
// All rights reserved.
//
// Use of this source code is governed by a AGPLv3 license that can be
// found in the LICENSE file.
package client

import (
	"encoding/hex"
	"fmt"
	"golang.org/x/net/context"
	utils "github.com/anysync/server/utils"
)

//==================================================================================================
// ===========================  Client Side ========================================================
//==================================================================================================

type RegisterData struct {
	//isNew, false, userID, response.DeviceID, newServer, err
	IsNewAccount     bool
	IsRestoreAccount bool
	LocalExists     bool
	UserID           string
	DeviceID         uint32
	ServerAddress    string
	Error            error
	ErrorCode        utils.AsErrorCode
}

func NewRegisterData(isNew , isRestore, localExists bool, userID string, deviceID uint32, server string, err error) *RegisterData {
	r := new(RegisterData)
	r.IsNewAccount = isNew
	r.IsRestoreAccount = isRestore
	r.LocalExists = localExists
	r.UserID = userID
	r.DeviceID = deviceID
	r.ServerAddress = server
	r.Error = err
	return r
}
func NewRegisterData2(isNew bool, isRestore bool, userID string, deviceID uint32, server string, err error, errCode uint32) *RegisterData {
	r := new(RegisterData)
	r.IsNewAccount = isNew
	r.IsRestoreAccount = isRestore
	r.UserID = userID
	r.DeviceID = deviceID
	r.ServerAddress = server
	r.Error = err
	r.ErrorCode = utils.AsErrorCode(errCode)
	return r
}

func ClientRegister(server string, port int, email, password, name string) (map[string][]byte, error) {
	tlsEnabled := utils.LoadAppParams().TlsEnabled//utils.IsOfficialSite(server)
	c, conn, err := utils.NewGrpcClientWithServer(server, port, tlsEnabled,  nil)
	if err != nil {
		utils.Warnf("did not connect: %v", err)
		return nil, err;
	}
	defer conn.Close()

	data := make(map[string][]byte)
	data["name"] = []byte(name)
	request := utils.UserRequest{
		Version:    utils.VERSION,
		Email:      email,
		Auth:       "",
		Data:       data,
	}

	response, err := c.Register(context.Background(), &request)
	return response.Data, err;
}

func ClientLogin(server string, port int, email, password, name string, isSignUp bool) *RegisterData {
	tlsEnabled := utils.LoadAppParams().TlsEnabled//  utils.IsOfficialSite(server)
	c, conn, err := utils.NewGrpcClientWithServer(server, port, tlsEnabled,  nil)
	if err != nil {
		utils.Warnf("did not connect: %v", err)
		return NewRegisterData2(false, false, "", 0, "", err, uint32(utils.ERROR_CDOE_TIME_OUT))
	}
	defer conn.Close()

	var encKey, authKey, rsaPriv, accessToken, rsaPub []byte
	var userID, deviceIDstring string
	data := make(map[string][]byte)
	data["name"] = []byte(name)
	data["storage"] = []byte(utils.LoadAppParams().RemoteNameCode)
	request := utils.UserRequest{
		Version:    utils.VERSION,
		Email:      email,
		Auth:       "",
		Data:       data,
	}

	isUserExistsLocally := true
	encKey, authKey, accessToken, rsaPriv, userID, deviceIDstring = userExistsLocally(email, password)
	localExists := false
	if encKey == nil {
		response, err := c.Login(context.Background(), &request)
		if err != nil {
			utils.Debug("could not finish ClientRegisterOrLogin: ", err)
			return NewRegisterData2(false, false, "", 0, "", err, uint32(utils.ERROR_CDOE_BAD_REQUEST))
		}
		if _, ok := response.Data[utils.LOGIN_KEY_TEXT]; ok { //already exists
			return doRestoreAccount(response, password, server, port, email, c)
		} else { //user does not exist, now we're going to create a brand new account.
			if !isSignUp {
				utils.Debug("User does not exist, and it's not signup")
				return NewRegisterData2(false, false, "", 0, "", err, uint32(utils.ERROR_CODE_UNAUTHROZID))
			}

			encKey = utils.GenerateKey()
			authKey = utils.GenerateKey()
			rsaPriv, rsaPub = utils.GenerateRsaKeys()
			isUserExistsLocally = false
			utils.Debug("UserExistsLocally is false")
			request.Auth = hex.EncodeToString(rsaPub) // fmt.Sprintf("%x", bs);
		}

	} else {
		utils.SetUserRequestNowWithAccessToken(&request, userID, deviceIDstring, accessToken)
		localExists = true
	}

	utils.Debug("User.Email: ", request.Email, "; To call ServerRegisterOrLogin on the main server again. deviceID: ", request.DeviceID)
	response, err := c.Login(context.Background(), &request)
	if err != nil {
		utils.Debug("could not finish ClientRegisterOrLogin: ", err)
		return NewRegisterData(false, false,  localExists,"", 0, "", err)
	}
	utils.Debug("User.ID is : ", response.User)
	var deviceID uint32
	userID = response.User
	if deviceIDstring == "" {
		deviceID = response.DeviceID
	} else {
		deviceID = utils.ToUint32(deviceIDstring)
	}
	utils.Debug("deviceID is ", deviceID)
	if accessToken != nil {
		utils.Debug("AccessToken:", fmt.Sprintf("%x", accessToken))
	}
	if accessToken == nil {
		accessToken = utils.FromHex(string(response.Data["token"]))
		utils.Debug("AccessToken2:", fmt.Sprintf("%x", accessToken))
		if accessToken, err = utils.RsaDecrypt(string(rsaPriv), accessToken); err != nil {
			utils.Debug("could not decrypt access token: ", err)
			return NewRegisterData(false, false, localExists, "", 0, "", err)
		}
	}
	isNewText := string(response.Data["isNew"])
	newServer := string(response.Data[utils.LOGIN_SERVER_TEXT])
	utils.Debug("isNewText: ", isNewText, "; userID: ", userID, "; accessToken: ", hex.EncodeToString(accessToken), "; serverIP:", server, "; newServer:", newServer)
	isNew := false
	if isNewText == "true" {
		isNew = true
	}
	ResetUserAndInitLocalServer(userID) //set content of "current" file.
	if !isUserExistsLocally {
		if err = utils.InitAccount(nil, []byte(password), accessToken, deviceID, userID, encKey, authKey, rsaPub, rsaPriv); err == nil {
			sendMasterKeyFile(userID, deviceID, accessToken, c)
		}
	}
	utils.CurrentAccessToken = accessToken
	tokenFile := utils.GetAccessTokenFile()
	if !utils.FileExists(tokenFile) {
		utils.SaveAccessToken(accessToken, tokenFile)
	}
	return NewRegisterData(isNew, false, localExists, userID, response.DeviceID, newServer, err)
}

func doRestoreAccount(response *utils.ActionResponse, password string, server string, port int, email string, c utils.SyncResultClient) *RegisterData {
	var userID, deviceIDstring string
	var deviceID uint32
	var encKey, authKey, rsaPriv, accessToken, rsaPub, masterKey []byte
	if deviceIDbs, ok := response.Data["device"]; ok {
		deviceIDstring = string(deviceIDbs)
		deviceID = utils.ToUint32(deviceIDstring)
	}
	utils.Debug("authenticated, deviceID: ", deviceIDstring)
	mkey := response.Data[utils.LOGIN_KEY_TEXT]
	newServer := string(response.Data[utils.LOGIN_SERVER_TEXT])
	if m, err := utils.DecryptMasterKeyBytes([]byte(password), []byte(mkey)); err != nil {
		utils.Info("Cannot decrypt master.keys sent from server.")
		return NewRegisterData(false, false,  false,"", 0, "", err)
	} else {
		masterKey = []byte(mkey)
		encKey = m["enc"]
		authKey = m["auth"]
		rsaPriv = m["priv"]
		accessToken = m["acc"]
		userID = response.User
		utils.SetClientMasterKeys(encKey, authKey)

		ResetUserAndInitLocalServer(userID) //set content of "current" file.
		if newServer != "" && newServer != server {
			server = newServer
		}
		utils.CreateConfigFile(utils.GetAppHome()+"config", email, userID, deviceID, server, port)
		if err = utils.InitAccount(masterKey, []byte(password), accessToken, deviceID, userID, encKey, authKey, rsaPub, rsaPriv); err != nil {
			utils.Debug("Error is ", err)
		}
		utils.CurrentAccessToken = accessToken
		sendConfirmDeviceID(userID, deviceID, accessToken, c)
		return NewRegisterData(false, true, false, userID, response.DeviceID, newServer, err)
	}

}

func sendMasterKeyFile(userID string, deviceID uint32, accessToken []byte, c utils.SyncResultClient) error {
	keyFile := utils.GetAppHome() + "data/" + utils.MASTER_KEY_FILE
	if bs, err := utils.Read(keyFile); err == nil {
		data2 := make(map[string][]byte)
		data2["key"] = (bs)
		dstr := fmt.Sprintf("%d", deviceID)
		utils.Debugf("before senddata, device: %d, string: %s", deviceID, dstr)
		dataRequest := utils.UserRequest{
			UserID: userID,
			Data:   data2,
		}
		utils.SetUserRequestNowWithAccessToken(&dataRequest, userID,  dstr, accessToken)
		dataRequest.Action = "key"
		_, err = c.SendData(context.Background(), &dataRequest)
		return err
	} else {
		return err
	}
}
