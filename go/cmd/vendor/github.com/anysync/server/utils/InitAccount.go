// Copyright (c) 2020, Yanbin (Henry) Zheng <ybzheng@gmail.com>
// All rights reserved.
//
// Use of this source code is governed by a AGPLv3 license that can be
// found in the LICENSE file.
package utils

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/golang/protobuf/proto"
	"github.com/golang/snappy"
	"golang.org/x/crypto/nacl/box"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/encoding"
	"google.golang.org/grpc/status"
	"io"
	"io/ioutil"
	"net/http"
	"sync"
	"time"
)

var _clientEncKey *[32]byte
var _clientAuthKey *[32]byte

var empty32 [32]byte

type SnappyCompressor struct{}

// Name is "snappy"
func (s SnappyCompressor) Name() string {
	return "snappy"
}

// Compress wraps with a SnappyReader
func (s SnappyCompressor) Compress(w io.Writer) (io.WriteCloser, error) {
	return snappy.NewBufferedWriter(w), nil
}

// Decompress wraps with a SnappyReader
func (s SnappyCompressor) Decompress(r io.Reader) (io.Reader, error) {
	return snappy.NewReader(r), nil
}
func init() {
	encoding.RegisterCompressor(SnappyCompressor{})
}

func SetClientMasterKeys(encKey, authKey []byte){
	var key [32]byte
	copy(key[:], encKey)
	_clientEncKey = &key;
	var auth [32]byte
	copy(auth[:], authKey)
	_clientAuthKey = &auth;
}

//Returns the 32-byte key for encrypting file, based on the master enc key and file hash
func GetFileEncKey(fileHash string) ([32]byte, error){
	if key, err := GetClientMasterAuthKey(); err != nil {
		return empty32, err;
	}else{
		h:=NewHmac(key[:]);
		h.Write([]byte(fileHash));
		bs := h.Sum(nil);
		var ret [32]byte;
		copy(ret[:], bs);
		return ret, nil;
	}
}

func GetClientMasterEncKey() ([32]byte, error) {
	if _clientEncKey == nil { //isAllZero(_clientEncKey)){
		if accessToken := GetAccessToken(); accessToken == nil {
			return empty32, errors.New("no access token retrieved")
		} else {
			keyFile := GetDataFolder()+"access.keys";
			if m, err := DecryptMasterKeys(accessToken, keyFile); err != nil {
				var bs [32]byte;
				return bs, err;
			}else {
				e := m["enc"]
				_clientEncKey = new([32]byte)
				copy((*_clientEncKey)[:], e)
				//Debug("GetClientMasterEncKey, MasterKey: ", hex.EncodeToString(e))
			}
		}
	}

	return *_clientEncKey, nil
}
func GetClientMasterAuthKey() ([32]byte, error) {
	if _clientAuthKey == nil {
		if accessToken := GetAccessToken(); accessToken == nil {
			return empty32, errors.New("no access token retrieved")
		} else {
			keyFile := GetDataFolder()+"access.keys";
			if m, err := DecryptMasterKeys(accessToken, keyFile); err != nil {
				var bs [32]byte;
				return bs, err;
			}else {
				e := m["auth"]
				_clientAuthKey = new([32]byte)
				copy((*_clientAuthKey)[:], e)
			}
		}
	}
	return *_clientAuthKey, nil
}

func GetClientPrivKey()(string, error){
	if accessToken := GetAccessToken(); accessToken == nil {
		return "", errors.New("no access token retrieved")
	} else {
		keyFile := GetDataFolder()+"access.keys";
		//Debug("AccessToken: ", hex.EncodeToString(accessToken), "; AccessKeyFile: ", keyFile)
		if m, err := DecryptMasterKeys(accessToken, keyFile); err != nil {
			return "", err;
		}else {
			return string(m["priv"]), nil;
		}
	}
}
func GetClientPubKey()([]byte, error){
	if accessToken := GetAccessToken(); accessToken == nil {
		return nil, errors.New("no access token retrieved")
	} else {
		keyFile := GetDataFolder()+"access.keys";
		if m, err := DecryptMasterKeys(accessToken, keyFile); err != nil {
			return nil, err;
		}else {
			return m["pub"], nil;
		}
	}
}

func GenerateKey() []byte {
	var err error
	var encKey []byte
	encKey, err = GenerateRandomBytes(32)
	if err != nil {
		return nil
	}
	return encKey
}

func GenerateRsaKeys() ([]byte,[]byte){

	pubKey, privKey, _ := box.GenerateKey(rand.Reader)
	return privKey[:], pubKey[:];
}

func InitAccount(masterKey []byte,  password, accessToken []byte, deviceID uint32, userID string, encKey, authKey, rsaPub, rsaPriv []byte) error {
	var err error
	dataFolder := GetDataFolder();
	if(dataFolder == ""){
		dataFolder = GetAppRoot() + "/" + userID + "/data/";
	}

	if(masterKey == nil) {
		//master.keys: store master keys using the scrypt(password).key as encryption key.
		if _, rsaPriv, err = SaveKeys(password, true, encKey, authKey, accessToken, rsaPub, rsaPriv, deviceID, dataFolder+MASTER_KEY_FILE); err != nil {
			return err
		}
	}else{
		WriteBytesSafe(dataFolder+MASTER_KEY_FILE, masterKey)
		if m, err := DecryptMasterKeyBytes(password, masterKey); err == nil {
			Debug("After decrypting master.keys file: " , dataFolder+MASTER_KEY_FILE, ".  we got: ")
			rsaPub = m["pub"]
			encKey = m["enc"]
			authKey = m["auth"]
			rsaPriv = m ["priv"]
		}
	}

	//access.keys: store master keys using the scrypt(accessToken).key as encryption key.
	if _, _, err = SaveKeys(accessToken, false, encKey, authKey, accessToken, rsaPub, rsaPriv, deviceID, dataFolder + ACCESS_KEY_FILE); err != nil {
		return err
	}

	if err := SaveAccessToken(accessToken, GetAccessTokenFile()); err != nil {
		return err
	}

	//Log.Info("InitAccount completed.")
	return nil
}

//This func used password to encrypt enc, RSA keys and saves them along with salt to a map.
//if keygen is false, the password must be 32 bytes.
//if RSA privKey is null, it generates a new RSA private key.
func SaveKeys(password []byte,  keygen bool, encKey, authKey, accessToken, rsaPub []byte, rsaPriv []byte, deviceID uint32, fileName string) ([]byte, []byte, error) {
	var err error
	attribs := FileAttribs{}
	attribs.Attribs = make(map[string][]byte)

	var k, salt []byte
	key := [32]byte{}
	if keygen {
		params := DefaultParams
		params.N = params.N + params.N
		k, salt, err = GenerateKeyFromPassword(password, salt, params)
		if err != nil {
			return nil, nil, err
		}

		copy(key[:], k)
	} else {
		copy(key[:], password)
	}

	attribs.Attribs["salt"] = salt
	bs, _ := Encrypt(encKey, &key)
	attribs.Attribs["enc"] = bs

	bs, _ = Encrypt(authKey, &key)
	attribs.Attribs["auth"] = bs

	bs, _ = Encrypt(accessToken, &key)
	attribs.Attribs["acc"] = bs

	bs, _ = Encrypt(rsaPub, &key)
	attribs.Attribs["pub"] = bs
	bs, _ = Encrypt(rsaPriv, &key)
	attribs.Attribs["priv"] = bs

	bs, err = proto.Marshal(&attribs)
	if err != nil {
		return nil, nil, err
	}
	Debug("Write key file: ", fileName)
	err = WriteBytesSafe(fileName, bs)
	return salt, rsaPriv, nil
}

//Get Masters by decrypting access key file (access.key)
func DecryptMasterKeys(password []byte, fileName string) (map[string][]byte,error) {
	//fileName := GetDataFolder() + "master.keys";
	if !FileExists(fileName) {
		return nil, errors.New("file does not exist")
	}
	bytes, err := Read(fileName)
	if err != nil {
		return nil, errors.New("cannot read file")
	}
	return DecryptMasterKeyBytes(password, bytes);
}

func DecryptMasterKeyBytes(password []byte, bytes []byte) (map[string][]byte,error) {
	attribs := FileAttribs{}
	if err := proto.Unmarshal(bytes, &attribs); err != nil {
		Error("Decrypt failed. Couldn't unmarshall.", err)
		return nil, err
	}
	salt := attribs.Attribs["salt"]
	key := [32]byte{}
	if salt == nil || len(salt) == 0 {
		//Debug("salt is nil or 0")
		copy(key[:], password)
	} else {
		params := DefaultParams
		params.N = params.N + params.N
		k, _, err := GenerateKeyFromPassword([]byte(password), salt, params)
		//Debug("In generateKeyFromPassword, password:", hex.EncodeToString(password), "; salt:", hex.EncodeToString(salt))
		if err != nil {
			Error("Decrypt failed. Couldn't derypt key", err)
			return nil, err
		}
		copy(key[:], k)
	}
	//Debug("In Decrypt, salt is ", hex.EncodeToString(salt), ", key is ", fmt.Sprintf("%x", key))
	decrypted, err := Decrypt(attribs.Attribs["enc"], &key)
	if err != nil {
		Error("Failed to decrypt enc key", err)
		return nil, err
	}
	attribs.Attribs["enc"] = decrypted

	decrypted, err = Decrypt(attribs.Attribs["auth"], &key)
	if err != nil {
		Error("Failed to decrypt auth key", err)
		return nil, err
	}
	attribs.Attribs["auth"] = decrypted

	decrypted, err = Decrypt(attribs.Attribs["acc"], &key)
	if err != nil {
		Debug("Failed to decrypt access token. ", err)
		return nil, err
	}
	attribs.Attribs["acc"] = decrypted

	decrypted, err = Decrypt(attribs.Attribs["pub"], &key)
	if err != nil {
		Error("Failed to decrypt pub key", err)
		return nil, err
	}
	attribs.Attribs["pub"] = decrypted

	decrypted, err = Decrypt(attribs.Attribs["priv"], &key)
	if err != nil {
		Error("Failed to decrypt priv key", err)
		return nil, err
	}
	attribs.Attribs["priv"] = decrypted

	return attribs.Attribs,nil
}

func RsaEncrypt(pubKeyToEncrypt []byte, plainText []byte, privKey , pubKey *[32]byte) []byte {
	var nonces [24]byte
	// This simply creates a random byte array
	rand.Read(nonces[:])
	var pubEncrytKey [32]byte
	copy(pubEncrytKey[:], pubKeyToEncrypt)

	var ret[]byte;
	ret = append(ret, pubKey[:]...)
	ret = append(ret, nonces[:]...)
	encrypted := box.Seal(nil, plainText, &nonces, &pubEncrytKey, privKey);
	ret = append(ret, encrypted...)
	return ret;
}

func RsaDecrypt( privKey string, encryptedAll []byte) ([]byte, error) {
	n := len(encryptedAll)
	if(n < 57){
		return nil, errors.New("encrypted message too short")
	}
	var pub [32]byte
	copy(pub[:], encryptedAll[0:32])
	ns := encryptedAll[32:56]
	var nonces [24]byte
	copy(nonces[:], ns)
	encrypted := encryptedAll[56:]
	var priv [32]byte
	copy(priv[:], []byte(privKey))

	if decrypted, b := box.Open(nil, encrypted, &nonces, &pub, &priv); b {
		return decrypted, nil;
	}else{
		return nil, errors.New("cannot be decrypted")
	}
}

var CurrentAccessToken []byte
var CurrentUser * UserAccount;
func SaveAccessToken(password []byte, fileName string) error {
	return WriteBytesSafe(fileName, password)
}
func GetAccessTokenFile() string{
	return GetDataFolder() + "session.dat"
}
func GetAccessToken() []byte {
	if CurrentAccessToken != nil {
		return CurrentAccessToken
	}
	if accessToken, err := RetrieveAccessToken(); err == nil {
		CurrentAccessToken = accessToken
	} else {
		Error("Error occurred in RetrieveAccessToken. Error: ", err)
		return nil
	}
	return CurrentAccessToken
}

func RetrieveAccessToken() ([]byte, error) {

	bs, err := Read(GetDataFolder() + "session.dat")
	if err != nil {
		return nil, err
	}
	return bs, err
}

type ReportEvent func(int,string)

func NewGrpcClient() (SyncResultClient, *grpc.ClientConn, error) {
	config := LoadConfig()
	if config == nil {
		Error("Config is nil")
		return nil, nil, errors.New("no config")
	}
	server := config.ServerAddress
	if config.ServerIp != ""{
		server = config.ServerIp
	}
	return NewGrpcClientWithServer(server, config.ServerPort, config.TlsEnabled, nil);
}

func NewGrpcClientWithServerAndDefaultPort(server string) (SyncResultClient, *grpc.ClientConn, error) {
	config := LoadConfig()
	return NewGrpcClientWithServer(server, config.ServerPort, config.TlsEnabled, nil);
}

func NewGrpcListenerClient(r ReportEvent) (SyncResultClient, *grpc.ClientConn, error) {
	config := LoadConfig()
	if config == nil {
		Error("Config is nil")
		return nil, nil, errors.New("no config")
	}
	return NewGrpcClientWithServer(config.ServerAddress, config.ServerPort, config.TlsEnabled, r);
}
func certPool(server string, port int) *x509.CertPool {
	//pem, err := ioutil.ReadFile("/tmp/server.crt")
	pem := GetPublicCert(server, port)
	if pem == nil {
		return nil
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(pem)
	return pool
}

func NewCredentials(serverAddress string, serverPort int)credentials.TransportCredentials{
	skip := LoadAppParams().TlsSkipVerify
	if(skip){
		return credentials.NewTLS(&tls.Config{
			InsecureSkipVerify: skip,
		})
	}else{
		return credentials.NewTLS(&tls.Config{
			RootCAs: certPool(serverAddress, serverPort),
			InsecureSkipVerify: skip,
		})
	}
}
func NewGrpcClientWithServer(serverAddress string, serverPort int, TlsEnabled bool, r ReportEvent) ( SyncResultClient, *grpc.ClientConn, error) {
	ip := fmt.Sprintf("%s:%d", serverAddress, serverPort) // fmt.Sprintf("%s:%d", config.serverAddress, config.serverPort);// "192.168.1.222"
	CurrentHost = serverAddress;
	Debug("NewGrpcClientWithServer. To aysnc connect to ", ip)
	var conn *grpc.ClientConn
	var err error
	ctx1, cel := context.WithTimeout(context.Background(), time.Second * 15) //15 seconds timeout
	defer cel()
	opts := grpc.WithDefaultCallOptions(grpc.UseCompressor("snappy"), grpc.MaxCallRecvMsgSize(1024*1024*512), grpc.MaxCallSendMsgSize(1024*1024*512))
	if TlsEnabled {
		Debug("TLS is enabled...skip verify:", LoadAppParams().TlsSkipVerify)
		creds := NewCredentials(serverAddress, serverPort)
		conn, err = grpc.DialContext(ctx1, ip, grpc.WithStreamInterceptor(NewStreamClientInterceptor(r)), grpc.WithBlock(),   grpc.WithTransportCredentials(creds), opts)
	} else {
		conn, err = grpc.DialContext(ctx1, ip, grpc.WithBlock(), grpc.WithInsecure(), opts)
	}
	if err != nil {
		Errorf("GRPC could not connect to ", serverAddress, "; error: %v", err)
		ok := false
		if (TlsEnabled && !LoadAppParams().TlsSkipVerify) {
			resetCert(serverAddress)
			//it may need a new public cert
			GetPublicCert(serverAddress, serverPort)
			creds := NewCredentials(serverAddress, serverPort)
			if conn, err = grpc.DialContext(ctx1, ip, grpc.WithStreamInterceptor(NewStreamClientInterceptor(r)), grpc.WithBlock(),   grpc.WithTransportCredentials(creds), opts); err == nil {
				ok = true
			}
		}
		if(!ok) {
			return nil, nil, errors.New("grpc couldn't connect to " + serverAddress)
		}
	}
	c := NewSyncResultClient(conn)
	return c, conn, nil
}

func  NewStreamClientInterceptor(r ReportEvent) func(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, streamer grpc.Streamer, opts ...grpc.CallOption) (grpc.ClientStream, error) {
	return func(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, streamer grpc.Streamer, opts ...grpc.CallOption) (grpc.ClientStream, error) {
		clientStream, err := streamer(ctx, desc, cc, method, opts...)
		if err != nil {
			return nil, err
		}
		return &monitoredClientStream{clientStream, r}, nil
	}
}

// monitoredClientStream wraps grpc.ClientStream allowing each Sent/Recv of message to increment counters.
type monitoredClientStream struct {
	grpc.ClientStream
	report ReportEvent
}

func (s *monitoredClientStream) SendMsg(m interface{}) error {
	err := s.ClientStream.SendMsg(m)
	return err
}

func (s *monitoredClientStream) RecvMsg(m interface{}) error {
	err := s.ClientStream.RecvMsg(m)
	if err == nil {
	} else if err == io.EOF {
	} else {
		Debug("RecvMsg Error is ", err)
		if(s.report != nil){
			st, _ := status.FromError(err)
			s.report(int(st.Code()), st.Message())
		}
	}
	return err
}

func NewGrpcUserRequest() *UserRequest {
	in := new(UserRequest)
	config := LoadConfig()
	return SetUserRequestNow(in, config.User, config.DeviceID)
}

func SetUserRequestNowWithAccessToken(in * UserRequest, userID, deviceID string , accessToken[]byte) * UserRequest{
	in.Version = VERSION;
	in.Server = LoadConfig().ServerAddress
	in.UserID = userID
	//in.DeviceName = deviceName
	in.DeviceID = uint32(ToInt(deviceID))
	t := uint32(time.Now().Unix());
	in.Time = t;
	in.Auth = CreateSignatureString(accessToken, userID,  t)
	return in
}

func SetUserRequestNow(in * UserRequest, userID, deviceID string) * UserRequest{
	in.Version = VERSION;
	in.Server = LoadConfig().ServerAddress
	in.UserID = userID
	in.DeviceID = uint32(ToInt(deviceID))
	t := uint32(time.Now().Unix());
	in.Time = t;
	token := GetAccessToken();
	in.Auth = CreateSignatureString(token, userID,  t)
	Debug("To calculate sig. user: ", userID, "; device: ", deviceID, "; time: ", t, "; accessToken:", hex.EncodeToString(token), "result.auth:", in.Auth)
	return in
}

func CreateSignature( userID string) (string, uint32){
	t := uint32(time.Now().Unix());
	return CreateSignatureString(GetAccessToken(), userID,  t), t
}

func CreateHttpAuthHeader() map[string]string{
	accessToken := GetAccessToken();
	if(accessToken == nil){return nil}
	conf := LoadConfig()
	ti := uint32(time.Now().Unix());
	t := fmt.Sprintf("%d", ti);

	return map[string]string{
		AS_USER: conf.User,
		AS_TIME: t,
		AS_DEVICE: conf.DeviceID,
		AS_AUTH: CreateSignatureString(accessToken, conf.User, ti),
	};
}



var certLock sync.Mutex
type CertData struct{
	CertTime uint32
	Cert [] byte
}

var certsMap map[string]*CertData;
func GetPublicCert(serverAddress string, serverPort int)[]byte{
	t := uint32(time.Now().Unix());
	var c *CertData
	if(certsMap != nil) {
		c = certsMap[serverAddress]
		if(c != nil) {
			if t-c.CertTime < 3600 && c.Cert != nil {
				return c.Cert
			}
		}
	}
	certLock.Lock()
	defer certLock.Unlock()
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}
	url := fmt.Sprintf("https://%s:%d/cert/" , serverAddress, serverPort)
	response, err := client.Get(url)
	if err != nil {
		return nil;
	}
	defer response.Body.Close()

	content, _ := ioutil.ReadAll(response.Body)
	if certsMap == nil {
		certsMap = make(map[string]*CertData)
	}
	c = &CertData{}
	c.Cert = content;
	c.CertTime = t;
	certsMap[serverAddress] = c;
	return content
}
func resetCert(serverAddress string){
	if certsMap == nil{
		return
	}
	if _, ok := certsMap[serverAddress]; ok{
		delete(certsMap, serverAddress)
	}
}
