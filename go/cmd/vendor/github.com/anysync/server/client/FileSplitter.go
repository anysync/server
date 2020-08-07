// Copyright (c) 2020, Yanbin (Henry) Zheng <ybzheng@gmail.com>
// All rights reserved.
//
// Use of this source code is governed by a AGPLv3 license that can be
// found in the LICENSE file.
package client

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"golang.org/x/sync/syncmap"
	"io"
	"os"
	utils "github.com/anysync/server/utils"
)

func createChunk(repository * utils.Repository, chnker *utils.Chunker, partFileName string) (* utils.Chunk, *utils.FileMeta, int64, error) {
	utils.Debugf("To create chunk: %s\n", partFileName)
	utils.SendMsg( "To create chunk file: " + utils.Basename2(partFileName))
	var packIncrement int64 = 0
	var fileMeta *utils.FileMeta
	chunk, err := startChunking(repository.Name, chnker, partFileName)
	if err != nil {
		if err != io.EOF || (err == io.EOF && chunk.Length == 0) {
			utils.Debug("To remove file:", partFileName)
			utils.RemoveFile(partFileName)
		}
		return nil, fileMeta, packIncrement, err
	}

	hashString := fmt.Sprintf("%x", chunk.Hash)
	base := utils.GetTopObjectsFolder() + utils.HashToPath(hashString)
	objFilePath := base + utils.EXT_OBJ
	if utils.DatFileExists(hashString) {
	//if utils.FileExists(base + utils.EXT_DAT) { //already there
		utils.RemoveFile(partFileName)
		return chunk, fileMeta, packIncrement, err
	}
	err = utils.Rename(partFileName, objFilePath)
	if err == nil {
		fileMeta = new(utils.FileMeta)
		fileMeta.SetFileHash( hashString);
		packIncrement = int64(chunk.Length);
		fileMeta.P = objFilePath;
	} else {
		utils.Debugf("Error renaming: %v\n", err)
	}

	return chunk, fileMeta, packIncrement, err
}

func startChunking(repository string, chnker *utils.Chunker, partFileName string) (*utils.Chunk, error) {
	var out *os.File
	var err error
	out, err = os.OpenFile(partFileName, os.O_WRONLY|os.O_CREATE|os.O_APPEND, utils.NEW_FILE_PERM)
	writer := bufio.NewWriter(out)
	//utils.Debugf("PartFileName:%s, chunkSize:%d\n", partFileName, chunkSize)
	if err != nil {
		return nil, err
	}
	defer closeWriterAndFile(writer, out)

	chunk, err := chnker.Next(repository, writer)
	if err != nil && err != io.EOF {
		return nil, err
	}

	return &chunk, err
}


func closeWriterAndFile(writer *bufio.Writer, f *os.File) {
	writer.Flush()
	f.Close()
}

const POL = utils.Pol(0x3DA3358B4DC173)

func SplitAndUpload(repository * utils.Repository, base string, objects *syncmap.Map,  deletes * syncmap.Map, fileHash string) ( error) {
	filename := base + utils.EXT_OBJ
	fileSize := utils.FileSize(filename)
	var subfile int64 = 0
	if fileSize < 1024*1024 {
		return  nil
	} //no need to split

	f, err := os.OpenFile(filename, os.O_RDONLY, 0)
	if err != nil {
		return  err
	}
	defer f.Close()

	var wholeBuf []byte
	fileMeta := new(utils.FileMeta)
	fileMeta.T = utils.FILE_META_TYPE_CHUNKS
	fileMeta.S = fileSize

	chnker := utils.New(f, POL)
	var hash []byte

	random := utils.GenerateRandomHash()
	var packSize int64 = 0
	var fileParts []*utils.FileMeta

	for subfile = 0; ; subfile++ {
		partFileName := fmt.Sprintf("%s/%s.%d", utils.GetTopTmpFolder(), random, subfile)
		chunk, meta, increment, err := createChunk(repository, chnker, partFileName)
		utils.Debugf("SplitAndUpload. packSize:%d, PartFileName:%s", packSize, partFileName)
		if err == io.EOF {
			break
		}
		if err != nil {
			return  err
		}
		if meta == nil { //the chunk already exists in the objects directory
			continue
		}

		packSize += increment
		fileParts = append(fileParts, meta)
		hash = append(hash, chunk.Hash...)
		wholeBuf = append(wholeBuf, chunk.Hash...)


		if packSize >= utils.PACK_FILE_SIZE_MAX_THRESHOLD {
			generateFinalPackFile(repository,  fileParts, objects,   deletes)
			fileParts = nil
			packSize = 0
		}
	}

	if packSize > 0 && len(fileParts) > 0 {
		utils.Debug("### ----  Leftover pack size:", packSize, "; packs.count: ", len(fileParts))
		generateFinalPackFile(repository,  fileParts, objects,   deletes)
	}

	fileMeta.P = encodeHashes(hash)
	fileMeta.SetFileHash(fileHash)
	objects.Store(fileHash, fileMeta)
	return   err
}

func encodeHashes(hashes []byte)string{
	return  base64.StdEncoding.EncodeToString(hashes);
}
