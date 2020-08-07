// Copyright (c) 2020, Yanbin (Henry) Zheng <ybzheng@gmail.com>
// All rights reserved.
//
// Use of this source code is governed by a AGPLv3 license that can be
// found in the LICENSE file.
package utils

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"
)

var HasGui  = false;
func SendToLocal(command string) {
	if  command == MSG_PREFIX {
		go sendEmptyMsg();
	}
	SendToLocalWithDelay(command, 0)
}

var lastSentMsg = time.Now()
var msgMutex = &sync.Mutex{}
//for sending informational message, with rate limiting
func SendMsg(msg string){
	msgMutex.Lock()
	defer msgMutex.Unlock()
	elapsed := time.Since(lastSentMsg)

	if(elapsed.Milliseconds()) < 200{
		return;
	}

	lastSentMsg = time.Now()
	SendToLocal(MSG_PREFIX + msg)
}

//@param delay in seconds
func SendToLocalWithDelay(command string, delay int64){
	if(!HasGui){
		return ;
	}
	if(delay > 0){
		time.Sleep(time.Duration(delay) * time.Second)
	}
	command = url.PathEscape(command);
	u := "http://localhost:65068/" + command;
	//Debug("localcppcommand. URL: " , u)
	HttpGetCommand(u, nil)
	return
}

func SendToLocalWithParams(command string, args ...string)error{
	command = url.PathEscape(command);
	n := len(args)
	text := ""
	for i:=0; i < n ; i+=2  {
		if( i != 0){
			text += "&"
		}
		text += args[i] + "=" + args[i+1]
	}
	text = url.PathEscape(text);
	u := "http://localhost:65068/" + command + "?" + text;
	//Debug("localcppcommand. URL: " , u)
	HttpGetCommand(u, nil)
	return nil
}

var lastSend uint32;
func sendEmptyMsg(){
	lastSend = 	uint32(time.Now().Unix());

	time.Sleep(30*time.Second)
	if(uint32(time.Now().Unix()) - lastSend > 25){
		SendToLocal(MSG_PREFIX)
	}
}

//Normal http command
func HttpGetCommand(url string, headers map[string]string) error{
	var client *http.Client;
	client = &http.Client{}
	request, _ := http.NewRequest("GET", url, nil)
	if(headers != nil) {
		SetHeaders(request, headers);
	}
	request.Close = true //close the connection to avoid "too many open files" issue.
	//Debug("To send out HTTP GET. URL: ", url)
	if response, err := client.Do(request) ; err != nil{
		Debug("Cannot connect to cpp client.")
		return err;
	} else {
		defer response.Body.Close()
		if(response.StatusCode != 200){
			return errors.New(fmt.Sprintf("Wrong status code %d", response.StatusCode));
		}
		return nil;
	}
}

func HttpGetFile(url, filename string, headers map[string]string) error{
	f, err := os.Create(filename)
	if(err != nil){
		Debug("HttpGetFile return, file: ", filename)
		return err;
	}
	defer f.Close()

	var client *http.Client;
	Debug("To create ignore cert client")
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client = &http.Client{Transport: tr}
	request, err := http.NewRequest("GET", url, nil)
	if(headers != nil) {
		SetHeaders(request, headers);
	}
	request.Close = true //close the connection to avoid "too many open files" issue.
	request.ContentLength = FileSize(filename)
	if response, err := client.Do(request) ; err != nil{
		Debug("HttpGetFile. URL:" , url,". Error occurred: ", err)
		return err;
	} else {
		defer response.Body.Close()
		if(response.StatusCode != 200){
			return errors.New(fmt.Sprintf("Wrong status code %d", response.StatusCode));
		}

		blen, err := io.Copy(f, response.Body)
		if(err != nil){Debug("Error is ", err); return err}
		Debug("Copy to ", filename , " with size: ", blen)
	}
	return nil;
}

func HttpPutFile(url, filename string, headers map[string]string) error{
	f, err := os.OpenFile(filename, os.O_RDONLY, 0);
	if err != nil { return err; }
	defer f.Close()
	var client *http.Client;
	Debug("To create ignore cert client")
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client = &http.Client{Transport: tr}
	request, err := http.NewRequest("PUT", url, f)
	if(headers != nil) {
		SetHeaders(request, headers);
	}
	request.Close = true //close the connection to avoid "too many open files" issue.
	request.ContentLength = FileSize(filename)
	if response, err := client.Do(request) ; err != nil{
		Debug("HttpPutFile returned error:", err)
		return err;
	} else {
		defer response.Body.Close()
		if(response.StatusCode != 200){
			return errors.New(fmt.Sprintf("Wrong status code %d", response.StatusCode));
		}
	}
	return nil;
}

func SetHeaders(request *http.Request, m map[string]string){
	for k, v := range m{
		request.Header.Set(k,v)
	}
}


