// Copyright (c) 2020, Yanbin (Henry) Zheng <ybzheng@gmail.com>
// All rights reserved.
//
// Use of this source code is governed by a AGPLv3 license that can be
// found in the LICENSE file.
package utils

import (
	"fmt"
	"gopkg.in/natefinch/lumberjack.v2"
	"log"
)

func init(){
}

func InitLogger(){
	if(TEST){
		return
	}
	var logFileName string;
	var name string;
	//argsWithoutProg := os.Args[1:]
	//n := len(argsWithoutProg);
	if(IS_MAIN_SERVER_SIDE){
		fmt.Println("It's main server.")
		h, _ := GetServerConfigDir();
		logFileName = h + "/logs/";
		name = "main.log"
	}else{
		logFileName = GetAppRoot() + "/logs/";
		name = "server.log"
	}
	if(FileExists(logFileName)){
		MkdirAll(logFileName)
	}
	logFileName += name;
	//fmt.Println("Log file is", logFileName)
	log.SetOutput(&lumberjack.Logger{
		Filename:   logFileName,
		MaxSize:    500, // megabytes
		MaxBackups: 15,
		MaxAge:     28,   // days
		Compress:   true, // disabled by default
	})

}
var logLevel = LOG_LEVEL_DEBUG

func SetLogLevel(l int){
	logLevel = l;
	//fmt.Println("Set logger level to", l)
}

func LogAccess(v ...interface{}){
	var w []interface{};
	w = append(w, "A");
	w = append(w, v...)
	log.Println( w ...);
}

func Critical(args ...interface{}) {
	if logLevel <= LOG_LEVEL_CRITICAL {
		log.Println( args...)
	}
}

func Error(args ...interface{}) {
	if logLevel <= LOG_LEVEL_ERROR {
		log.Println( args...)
	}
}

func Warn(args ...interface{}) {
	if logLevel <= LOG_LEVEL_WARN {
		log.Println( args...)
	}
}

func Info(args ...interface{}) {
	if logLevel <= LOG_LEVEL_INFO {
		log.Println( args...)
	}
}

func Debug(args ...interface{}) {
	if logLevel <= LOG_LEVEL_DEBUG {
		log.Println( args...)
	}
}

func Errorf(text string, args ...interface{}) {
	if logLevel <= LOG_LEVEL_ERROR {
		out := fmt.Sprintf(text, args...)
		log.Println(out);//text,  args)
	}
}


func Warnf(text string, args ...interface{}) {
	if logLevel <= LOG_LEVEL_WARN {
		out := fmt.Sprintf(text, args...)
		log.Println(out);//text,  args)
	}
}

func Infof(text string, args ...interface{}) {
	if logLevel <= LOG_LEVEL_INFO {
		out := fmt.Sprintf(text, args...)
		log.Println(out);//text,  args)
	}
}

func Debugf(text string, args ...interface{}) {
	if logLevel <= LOG_LEVEL_DEBUG {
		out := fmt.Sprintf(text, args...)
		log.Println(out);//text,  args)
	}
}
