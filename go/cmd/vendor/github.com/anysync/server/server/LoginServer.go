// Copyright (c) 2020, Yanbin (Henry) Zheng <ybzheng@gmail.com>
// All rights reserved.
//
// Use of this source code is governed by a AGPLv3 license that can be
// found in the LICENSE file.
package server

import (
	"errors"
	"fmt"
	"golang.org/x/net/context"
	"google.golang.org/grpc/peer"
	"regexp"
	utils "github.com/anysync/server/utils"
)

//==================================================================================================
// ===========================  Server Side ========================================================
//==================================================================================================
func (s *remoteserver) Register(ctx context.Context, in *utils.UserRequest) (*utils.ActionResponse, error) {
	//if !utils.IsVersionOk(in.Version) {
	//	return utils.NewActionResponseWithError(utils.ERROR_CODE_BAD_VERSION), errors.New("wrong version")
	//}
	//email := strings.ToLower(in.Email)
	//if(!isValidEmail(email)){
	//	return utils.NewActionResponseWithError(utils.ERROR_CDOE_BAD_REQUEST), errors.New("error")
	//}
	//user, errCode := GetUserAccount(email)
	//if errCode != 0 {
	//	utils.Info("GetUserAccount, error:", errCode)
	//	return utils.NewActionResponseWithError(errCode), errors.New("error")
	//}
	//deviceID := in.DeviceID // uint32(0)
	//
	//utils.Info("Register Email:", email)
	//m := make(map[string][]byte)
	//response := utils.ActionResponse{
	//	DeviceID: deviceID,
	//	Data:     m,
	//}
	//
	//if user != nil {
	//	utils.Info("user already exists:", email)
	//	return &response, errors.New("user already exists") //errors.New("no password and no user found");
	//}
	//
	////save it to file
	//hash := CreateHash(email);
	//dir := utils.GetRootOnServer() + "register";
	//if utils.FileExists(dir) {
	//	utils.MkdirAll(dir)
	//}
	//ip := ""
	//if p, ok := peer.FromContext(ctx); ok{
	//	ip = p.Addr.String();
	//}
	//fileName := dir + "/" + hash
	//if utils.FileExists(fileName){
	//	text, _ := utils.ReadString(fileName)
	//	if strings.TrimSpace(text) == "ok" {
	//		utils.Info("file already exists:", fileName)
	//		response.Data["registered"] = []byte("true");
	//		return &response, nil
	//	}
	//}
	//utils.WriteString(fileName, ip + "\n" + time.Now().String())
	////To send verification email:
	//body := "Thank you for your request to register an AnySync account.\r\n\r\n"
	//body += "Please click the link below to proceed.\nhttps://anysync.net/verify.php?email=" + email + "&code=" + hash
	//body += "\r\n\r\nThis is an automated message - do not reply to this email. If you didn't request this email, please ignore it."
	//err := SendMail("AnySync Activation", email, "AnySync account activation", body)
	//if err != nil {
	//	utils.Info("Email error:", err)
	//}
	//return &response, err

	return nil, nil
}

func (s *remoteserver) Login(ctx context.Context, in *utils.UserRequest) (*utils.ActionResponse, error) {
	ip := ""
	if p, ok := peer.FromContext(ctx); ok{
		ip = p.Addr.String();
	}
	if !utils.IsVersionOk(in.Version) {
		return nil, errors.New(fmt.Sprintf("%d", utils.ERROR_CODE_BAD_VERSION))
	}
	if(!isValidEmail(in.Email)){
		utils.Info("In.Email is invalid:", in.Email)
		return nil, errors.New(fmt.Sprintf("%d", utils.ERROR_CDOE_BAD_REQUEST))
	}
	utils.Info("In.Email is valid:", in.Email)
	user, errCode := GetUserAccount(in.Email)
	if errCode != 0 {
		return utils.NewActionResponseWithError(errCode), errors.New("error")
	}
	deviceID := in.DeviceID
	name := string(in.Data["name"])
	storageNameCode := string(in.Data["storage"])
	if !utils.LoadAppParams().IsRemoteNameCodeAllowed(storageNameCode) {
		return nil, errors.New(fmt.Sprintf("%d", utils.ERROR_CDOE_BAD_REQUEST))
	}
	isNew := false

	m := make(map[string][]byte)
	response := utils.ActionResponse{
		DeviceID: deviceID,
		Data:     m,
	}

	var pubKey []byte
	var err error
	if user == nil {
		utils.Debug("user is nil.")
		isNew = true
		if in.Auth != "" {
			//if !VerificationFileExists(in.Email){ // this email has not been verified yet
			//	return nil, errors.New("not registered:" + in.Email)
			//}

			if user, err = AddUserAccount(in.Email, in.Auth, name, ip, storageNameCode); err == nil {
				utils.Debug("Added new user ", user.ID)
				response.Data[utils.LOGIN_SERVER_TEXT] = []byte(user.Server)
				pubKey = user.PubKey;//, _ = hex.DecodeString(in.Auth)
			} else {
				utils.Info("Cannot add user")
				return nil, err
			}
		} else {
			//it's fine, don't return error. Client sends such request to check if user name already exists
			return &response, nil //errors.New("no password and no user found");
		}
	}

	response.User = fmt.Sprintf("%d", user.ID)
	utils.Debug("user id is ", user.ID, "; accessToken: ", fmt.Sprintf("%x", user.AccessToken))
	if pubKey == nil {
		utils.Debug("pubkey is nil, use user.PubKey:", fmt.Sprintf("%x", user.PubKey))
		pubKey = user.PubKey
	}
	serverPriv, serverPub := GetMainServerRsaKeys()
	encrypted := utils.RsaEncrypt(pubKey, user.AccessToken, serverPriv, serverPub) // fmt.Sprintf("%x", user.AccessToken);
	utils.Debug("AccessToken:", fmt.Sprintf("%x", encrypted))
	m["token"] = []byte(fmt.Sprintf("%x", encrypted))
	m["isNew"] = []byte(fmt.Sprintf("%v", isNew))
	if !isNew {
		if in.Auth != "" {
			utils.Debug("In.Auth is not empty.")
			if !AuthenticateUserAccount(user, in.Auth, in.Time) {
				utils.Debug("In server.go: Auth failed for user: ", user.Email)
				return nil, errors.New("auth failed")
			} else { //user already exists
				utils.Debug("In server.go: Authenticated userID: ", user.ID, "; email: ", user.Email, "; ~~~deviceID count: ", user.MaxID, ", in.DeviceID: ", in.DeviceID)
				user.MaxID ++;
				UpdateUserAtRootServer(user, false)
			}
		} else { //client is trying to get server side data without providing auth. It's happened when log in to a brand new deviceID
			utils.Debug("In server.go: Authenticated userID: ", user.ID, "; email: ", user.Email, "; ===deviceID count: ", user.MaxID)
			//user.Devices[deviceID] =in.DeviceName;
			//UpdateUserInDb(user)
			m["device"] = []byte(fmt.Sprintf("%d", user.MaxID))
			repo := utils.GetUserRootOnServer(fmt.Sprintf("%d", user.ID))
			file := repo + "/data/master.keys"
			utils.Debug("MasterKeyFile: ", file)
			if fileData, err := utils.ReadString(file); err == nil {
				utils.Debug("Found user's masterkey file. Already read content of master key file")
				m[utils.LOGIN_KEY_TEXT] = []byte(fileData)
				m[utils.LOGIN_SERVER_TEXT] = []byte(user.Server)
				return &response, nil
			} else {
				utils.Debug("Cannot find user's masterkey.")
				return nil, errors.New(fmt.Sprintf("%d", utils.ERROR_CDOE_BAD_REQUEST))
			}
		}
	}

	return &response, nil
}





var (
	emailRegexp = regexp.MustCompile(	 "^[\\w!#$%&'*+/=?`{|}~^-]+(?:\\.[\\w!#$%&'*+/=?`{|}~^-]+)*@(?:[a-zA-Z0-9-]+\\.)+[a-zA-Z]{2,6}$")
)

func isValidEmail(email string) bool {
	if len(email) < 2 {
		return false
	}
	if !emailRegexp.MatchString(email) {
		return false
	}
	return true
}
