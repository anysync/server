// Copyright (c) 2020, Yanbin (Henry) Zheng <ybzheng@gmail.com>
// All rights reserved.
//
// Use of this source code is governed by a AGPLv3 license that can be
// found in the LICENSE file.

package utils

import (
	"fmt"
	"math"
	"strconv"
	"strings"
)
const(
	BIN_TYPE_FILE_LOG   = uint8(1);
	BIN_TYPE_FILE_BIN   = uint8(2);
	BIN_TYPE_SERVER_BIN = uint8(3);

	DEFAULT_SPLIT_THRESHOLD = math.MaxUint32// uint32(1024*1024*2);
)


type BinIO struct {
	Base, fileName   string
	binType          uint8
	canRotate        bool
	rowSize          uint32;
	currentRowCount  uint32;
	previousRowCount uint32;
}

func init() {
}

func NewMetaBinIO( base string, isLog bool) *BinIO {
	if(isLog) {
		return NewBinIO( base, BIN_TYPE_FILE_LOG);
	}else{
		return NewBinIO(base, BIN_TYPE_FILE_BIN);
	}

}

func NewBinIO( baseFileName string, binType uint8) *BinIO {
	db := new(BinIO);
	db.Base = baseFileName;
	db.binType = binType;
	db.canRotate = true;
	switch binType{
	case BIN_TYPE_FILE_BIN:
		db.rowSize = FILE_INFO_BYTE_COUNT;
		db.fileName = baseFileName + ".bin"
		db.canRotate = false;
	case BIN_TYPE_FILE_LOG , BIN_TYPE_SERVER_BIN:
		db.rowSize = FILE_INFO_BYTE_COUNT;
		db.fileName = baseFileName + ".log"
		if(binType == BIN_TYPE_SERVER_BIN){
			db.rowSize = SERVER_LOG_BIN_ROW_SIZE;
			db.fileName = baseFileName + ".bin" //server.bin
			Debug("bin file name is ", db.fileName)
		}
		fileSize:=FileSize(db.fileName);
		bixFile := baseFileName + ".bix";
		db.previousRowCount = uint32(0);
		db.currentRowCount += uint32( fileSize /int64(db.rowSize))
		if(FileExists(bixFile)){
			contents, err := ReadString(bixFile)
			if(err == nil) {
				pos := strings.Index(contents, ",");
				i, _ := strconv.Atoi(contents[0:pos]);
				db.previousRowCount = uint32(i)
			}
		}
	}
	return  db;
}

func WriteFileInfoBin(base string, offset int64, row[]byte){
	db := NewMetaBinIO(base, false);
	db.Update(offset, row);
}

func (db *BinIO) Update(offset int64, entry []byte) (err error) {
	//Debugf("To update file:%s, offset:%d, data: %x\n", db.fileName, offset, entry)
	return UpdateFileSafe(db.fileName, offset, entry);
}

func (db *BinIO) Append(entry []byte) (err error) {
	return db.AppendWithRotateCheck(entry, db.canRotate);
}

// Write will write binary entry
func (db *BinIO) AppendWithRotateCheck(entry []byte , checkRotate bool) (err error) {
	if(checkRotate) {
		newRowCount := uint32(uint32(len(entry)) / db.rowSize);
		//Debugf("CurrentRowSize:%d, newRowCount:%d, logFile:%s\n", db.currentRowCount, newRowCount, db.fileName)
		if db.currentRowCount+newRowCount > DEFAULT_SPLIT_THRESHOLD {
			//Debugf("To split. newRowCount:%d\n", newRowCount)
			pos := (db.currentRowCount + newRowCount - DEFAULT_SPLIT_THRESHOLD - 1) * db.rowSize;
			if(pos > 0) {
				db.AppendWithRotateCheck(entry[0:pos], false);
			}
			db.rotate()
			entry = entry[pos:];
		}
	}
	//Debugf("To append to file: %s, len:%d. beforeAppend row.count:%d\n", db.fileName, len(entry), db.currentRowCount)
	err = AppendBytes(db.fileName, entry)
	if(err == nil && db.canRotate){
		db.currentRowCount += uint32( uint32(len(entry)) /db.rowSize)
	}
	return
}

func (db BinIO) GetRowCount()uint32{
	return db.previousRowCount + db.currentRowCount;
}

func (db *BinIO) rotate() (err error) {
	bixFile := db.Base + ".bix";
	contents, err := ReadString(bixFile)
	var previousCount uint32;
	var text string;
	max := 0;
	if(err == nil) {
		pos := strings.Index(contents, ",");
		if(pos > 0) {
			i,_ := strconv.Atoi(contents[0:pos]);
			previousCount = uint32(i)
			text = contents[pos+1:];
			tokens := strings.Split(text, ",");
			for _,token := range tokens{
				i, _:= strconv.Atoi(token);
				if(i > max){
					max = i;
				}

			}
		}
	}

	max++;
	err =Rename(db.fileName, fmt.Sprintf("%s.%d", db.fileName , max));
	if(err == nil){
		if(len(text) == 0){
			contents = fmt.Sprintf("%d,%d", previousCount+DEFAULT_SPLIT_THRESHOLD,  max);
		}else {
			contents = fmt.Sprintf("%d,%s,%d", previousCount+DEFAULT_SPLIT_THRESHOLD, text, max);
		}

		WriteString(bixFile, contents)
	}
	db.currentRowCount = 0;
	return
}

