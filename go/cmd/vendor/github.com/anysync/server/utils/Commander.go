// Copyright (c) 2020, Yanbin (Henry) Zheng <ybzheng@gmail.com>
// All rights reserved.
//
// Use of this source code is governed by a AGPLv3 license that can be
// found in the LICENSE file.

package utils

import (
	"bytes"
	"errors"
	"net"
	"os"
	"os/exec"
	"os/user"
	"strings"
)

func GetSystemFingerprint() string{
	u, _ := user.Current()
	//fmt.Printf("Here user is <%v>. UID:%s, GID:%s, username:%s\n", u, u.Uid, u.Gid, u.Username)
	host, _ := os.Hostname()
	macs := getMacs();
	if(IsWindows()){
		osSerial, hwSerial := getMachineIdOnWin();
		return Md5Text(u.Uid + "|" + u.Gid + "|" + u.Username + "|" + host + "|" + osSerial + "|" +hwSerial + "|" + macs);
	}else if(IsMac()){
		osSerial, hwSerial := getMachineIdOnMac();
		return Md5Text(u.Uid + "|" + u.Gid + "|" + u.Username + "|" + host + "|" + osSerial + "|" +hwSerial + "|" + macs);
	}else {//linux if(IsLinux()){
		osSerial, hwSerial := getMachineIdOnLinux();
		return Md5Text(u.Uid + "|" + u.Gid + "|" + u.Username + "|" + host + "|" + osSerial + "|" +hwSerial + "|" + macs);
	}
}

func getMachineIdOnLinux() (string, string) {
	osInfo, _ := RunCommand("uname", []string{"-a"})
	return osInfo, ""
}

func getMacs() string {
	var macs []string
	interfaces, _ := net.Interfaces()
	for _, interf := range interfaces {
		if len(interf.HardwareAddr) > 0 {
			macs = append(macs, interf.HardwareAddr.String())
		}
	}
	return strings.Join(macs, ";")
}

func getSecondLine(command string, args []string) (string, error) {
	text, err := RunCommand(command, args)
	if err != nil {
		return "", err
	}
	lines := strings.Split(text, "\n")
	if len(lines) < 2 {
		return "", errors.New("invalid")
	}
	return strings.TrimSpace(lines[1]), nil
}

//Returns OS serial number and hardware UUID
func getMachineIdOnWin() (string, string) {
	osSerial, _ := getSecondLine("wmic", []string{"os", "get", "serialnumber"})
	biosSerial, _ := getSecondLine("wmic", []string{"bios", "get", "serialnumber"})
	return osSerial, biosSerial
}

func getValue(sub string) string {
	var user string
	toAppend := false
	for _, elem := range sub {
		if elem == '"' {
			if len(user) > 0 {
				break
			} else {
				toAppend = true
				continue
			}
		}
		if toAppend {
			user += string(elem)
		}
	}
	return strings.TrimSpace(user)
}

//Returns OS serial number and hardware UUID
func getMachineIdOnMac() (string, string) {
	text, err := RunCommand("ioreg", []string{"-l"})
	if err != nil {
		return "", ""
	}
	foundSerialNumber := false
	foundHardwareUUID := false
	lines := strings.Split(text, "\n")
	var serialNumber, hardwareUUID string
	for _, line := range lines {
		// "IOPlatformSerialNumber" = "DCPQJ67PGDQY"  "IOPlatformUUID" = "A282C9C4-696C-5718-B248-6BB93BAD08DC"
		if !foundSerialNumber {
			pos := strings.Index(line, "IOPlatformSerialNumber")
			if pos > 0 {
				foundSerialNumber = true
				pos += len("IOPlatformSerialNumber")
				sub := line[pos+1:]
				serialNumber = getValue(sub)
			}
		}
		if !foundHardwareUUID {
			pos := strings.Index(line, "IOPlatformUUID")
			if pos > 0 {
				foundHardwareUUID = true
				pos += len("IOPlatformUUID")
				sub := line[pos+1:]
				hardwareUUID = getValue(sub)
			}
		}
		if foundSerialNumber && foundHardwareUUID {
			return serialNumber, hardwareUUID
		}
	}
	return serialNumber, hardwareUUID
}

func RunCommand(cmdName string, args []string) (string, error) {
	var (
		cmdOut []byte
		err    error
	)
	var stderr bytes.Buffer
	cmd := exec.Command(cmdName, args...);
	cmd.Stderr = &stderr
	if cmdOut, err = cmd.Output(); err != nil {
		Debug("There was an error running command: ", cmdName, "; args: ", args, "; error is ", stderr.String())
		return string(cmdOut), err
	}
	return string(cmdOut), err
}
