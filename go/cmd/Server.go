// Copyright (c) 2020, Yanbin (Henry) Zheng <ybzheng@gmail.com>
// All rights reserved.
//
// Use of this source code is governed by a AGPLv3 license that can be
// found in the LICENSE file.
package main

import (
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"github.com/soheilhy/cmux"
	"google.golang.org/grpc"
	"log"
	"math"
	"net"
	"net/http"
	"os"
	server "github.com/anysync/server/server"
	"strings"
	"time"
	utils "github.com/anysync/server/utils"
)

func initMainServer(){
	go server.HandleIncompleteServerTasks()
}


func checkHttpAuth( r *http.Request) (bool, *utils.UserAccount){
	uid := r.Header.Get(utils.AS_USER)
	user, err := server.GetUserAccountByID(utils.ToInt(uid))
	if(err != 0){
		utils.Debug("DbServer is not functioning.", uid)
		return false , nil;
	}
	if(user == nil){
		utils.Debug("UserID does not exist: ", uid)
		return false, user
	}
	auth := r.Header.Get(utils.AS_AUTH);
	ti := r.Header.Get(utils.AS_TIME);
	h := utils.CreateSignatureString(user.AccessToken, uid,  uint32(utils.ToInt(ti)));
	return h == auth, user;
}

var grpcServer *grpc.Server;
var httpServer *http.Server;
var lsner net.Listener;

func startMainServer() {
	initMainServer()

	var certFile, keyFile string;
	l, err := net.Listen("tcp", utils.MAIN_PORT)
	if err != nil { log.Fatalf("failed to listen: %v", err) }

	p := utils.LoadAppParams()
	config := utils.LoadServerConfig();
	lsner = l;

	if(p.TlsEnabled) {
		configDir, _ := utils.GetServerConfigDir();
		certFile = config.CertFile;
		if (strings.Index(certFile, "/") < 0 && strings.Index(certFile, "\\") < 0) {
			certFile = configDir + "/" + certFile;
		}
		keyFile = config.KeyFile;
		if (strings.Index(keyFile, "/") < 0 && strings.Index(keyFile, "\\") < 0) {
			keyFile = configDir + "/" + keyFile;
		}
		lsner = NewTlsListener(certFile, keyFile, l)// tls.NewListener(l, tlsconfig)

		file, _ := os.Stat(keyFile)
		modifiedtime := file.ModTime()
		go func() {
			for {
				time.Sleep(10 * time.Minute)
				file, _ = os.Stat(keyFile)
				modifiedtime2 := file.ModTime()
				if (modifiedtime2.Unix() > modifiedtime.Unix()) {
					modifiedtime = modifiedtime2;
					utils.Info("Key file modified...")
					httpServer.Close()
					grpcServer.GracefulStop()
					lsner.Close();
				}
			}
		}()
	}
	serve(certFile, keyFile);

}

func serve(certFile, keyFile string){
	for{
		m := cmux.New(lsner)
		//order of m.Match matters!
		//refer to https://github.com/soheilhy/cmux/blob/master/example_tls_test.go
		// We first match on HTTP 1.1 methods.
		httpL := m.Match(cmux.HTTP1Fast())
		// If not matched, we assume that its TLS.
		grpcL := m.Match(cmux.Any());//cmux.HTTP2HeaderField("content-type", "application/grpc"))

		grpcS := NewGrpcServer();
		grpcServer = grpcS
		httpS := & http.Server{Handler:  & http1Handler{}};
		httpServer = httpS;
		httpS.SetKeepAlivesEnabled(false) //critical, otherwise it'll cause "too many open files" error. (http2 server always keep connection open)
		go httpS.Serve(httpL);

		server.RegisterServer(grpcS)

		utils.Info("Main server started at port: ", utils.MAIN_PORT)
		go grpcS.Serve(grpcL)
		err := m.Serve()
		utils.Info("m.Serve returned. err:", err);
		lsner.Close();
		time.Sleep(1*time.Second);
		lsner , _ = net.Listen("tcp", utils.MAIN_PORT)
		if len(certFile) > 0  {
			lsner = NewTlsListener(certFile, keyFile, lsner)
		}
     }
}

func NewTlsListener(certFile, keyFile string, l net.Listener)net.Listener{
	cer, err := tls.LoadX509KeyPair(certFile, keyFile)
	if(err != nil){
		log.Println("Error loading cert file", err)
		return nil;
	}
	tlsconfig := &tls.Config{
		Certificates: []tls.Certificate{cer},
		Rand:         rand.Reader,
	}
	return tls.NewListener(l, tlsconfig)
}

func NewGrpcServer()*grpc.Server{
	opts := []grpc.ServerOption{
		// The limiting factor for lowering the max message size is the fact
		// that a single large kv can be sent over the network in one message.
		// Our maximum kv size is unlimited, so we need this to be very large.
		grpc.MaxRecvMsgSize(math.MaxInt32),
		// The default number of concurrent streams/requests on a client connection
		// is 100, while the server is unlimited. The client setting can only be
		// controlled by adjusting the server value. Set a very large value for the
		// server value so that we have no fixed limit on the number of concurrent
		// streams/requests on either the client or server.
		grpc.MaxConcurrentStreams(math.MaxInt32),
	}
	return grpc.NewServer(opts...);
}

type http1Handler struct{}

func (h *http1Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	fmt.Printf("ServeHTTP.request.url: %v; path:%s; headers:\n%v\n",r.URL, r.URL.Path, r.Header);
	url := r.URL.Path;
	if  r.Header.Get(utils.AS_USER) != "" || strings.HasPrefix(url, "/put/") { //own internal requests
		fmt.Println("To call handleInternalHttpRequest")
		handleInternalHttpRequest(w, r)
		return;
	}
	if(strings.HasPrefix(url, "/cert/")) { //get cert
		config := utils.LoadServerConfig();
		configDir, _ := utils.GetServerConfigDir();

		file :=  configDir + "/" +  config.CertFile
		if(utils.FileExists(file)){
			http.ServeFile(w, r, file)
		} else {
			utils.Debug("File doesn't exist: ", file)
		}
		return;
	}

	//utils.Debug("Not internal request.")

	if auth := r.Header.Get("Authorization") ; (auth == "" &&  !utils.TEST){
		utils.Debug("Error. Not authorized. No 'Authorization' header.")
		http.Error(w, "Not Authorized", 401)
		return;
	}
	return;
}

//Handle http request from own go server.
func handleInternalHttpRequest(w http.ResponseWriter, r *http.Request){
	urlString := r.URL.Path;
	utils.Debug("Enter handleInternalHttpRequest, url: ", urlString)
	if(strings.HasPrefix(urlString, "/tmp/")) { //called from Rescan.go::resetGetAllDownloadFile()
		b, user := checkHttpAuth(r)
		if(!b){
			utils.Debug("HTTP Auth failed")
			http.Error(w, "Not Authorized", 401)
			return;
		}
		utils.Debug("HTTP Auth OK")
		file := utils.GetTmpOnServer() + urlString[5:];
		utils.Debug("request file is ", file)
		if (utils.FileExists(file)) {
			http.ServeFile(w, r, file)
		} else {
			utils.Debug("File doesn't exist: ", file)
		}
		userID := fmt.Sprintf("%d", user.ID);
		deviceID := r.Header.Get(utils.AS_DEVICE)
		server.SaveClientsDatFile(userID, deviceID, 0, "",0, false)
		utils.RemoveFile(file);
		return;
	}else if(strings.HasPrefix(urlString, "/put/")){  //called from client side Rescan.go::processChangesLocally()
		utils.Debug("Has prefix put...")



			server.PutHandler(w, r)

	}
}

func main() {
	utils.IS_MAIN_SERVER_SIDE = true;
	utils.InitLogger();
	fmt.Println("To start main server.")
	utils.LoadServerConfig()
	server.OpenUserDB(utils.GetRootOnServer() + "data/data.db")


	startMainServer()
}


