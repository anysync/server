// Copyright (c) 2020, Yanbin (Henry) Zheng <ybzheng@gmail.com>
// All rights reserved.
//
// Use of this source code is governed by a AGPLv3 license that can be
// found in the LICENSE file.
package client

import (
	"github.com/kr/binarydist"
	"os"
	utils "github.com/anysync/server/utils"
)

func diff(newFileName string, newFileSize int64, oldFileHash string) (bool, string, int64) {
	oldFileName := utils.GetTopObjectsFolder() + utils.HashToPath(oldFileHash) + utils.EXT_OBJ
	if !utils.FileExists(oldFileName) {
		GetCloudFile(oldFileName, "", oldFileName)
	}
	oldFile, _ := os.OpenFile(oldFileName, os.O_RDONLY, 0)
	newFile, _ := os.OpenFile(newFileName, os.O_RDONLY, 0)
	tmpFileName := utils.GetTopTmpFolder() + utils.GenerateRandomHash()
	deltaFile, _ := os.OpenFile(tmpFileName, os.O_WRONLY|os.O_CREATE, utils.NEW_FILE_PERM)
	defer oldFile.Close()
	defer deltaFile.Close()
	defer newFile.Close()

	binarydist.Diff(oldFile, newFile, deltaFile)

	var ret bool = false
	size := utils.FileSize(tmpFileName)
	if size < int64(float64(newFileSize)*0.2) {
		ret = true
	}
	return ret, tmpFileName, size
}

func patch(oldFileName string, destFileName string, deltaFileName string) error {
	oldFile, _ := os.OpenFile(oldFileName, os.O_RDONLY, 0)
	obj, _ := os.OpenFile(destFileName, os.O_WRONLY|os.O_CREATE, utils.NEW_FILE_PERM)
	deltaFile, _ := os.OpenFile(deltaFileName, os.O_RDONLY, 0)
	defer oldFile.Close()
	defer deltaFile.Close()
	defer obj.Close()
	err := binarydist.Patch(oldFile, obj, deltaFile)
	if err != nil {
		return err
	}
	return nil
}
