// Copyright (c) 2020, Yanbin (Henry) Zheng <ybzheng@gmail.com>
// All rights reserved.
//
// Use of this source code is governed by a AGPLv3 license that can be
// found in the LICENSE file.

package utils

import (
	"github.com/pierrec/lz4"

	"archive/tar"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func CreateZip(folders []string, transformMap map[string]string, excludedExts []string, zipFileName string)error{
	Debugf("To zip folders: %v", folders)
	Debugf("Zip file is %s", zipFileName)
	return  Make(zipFileName, folders, transformMap, excludedExts) //archiver.TarLz4.Make(tmpDir + zipFileName, folders)
}

//The zip file must end with ".lz4"!
func UnzipTo(zipFile, directory string) error {
	//err := archiver.Unarchive(zipFile, directory)
	r, err := os.Open(zipFile)
	if err != nil {
		return err
	}
	defer r.Close()

	uncompressedStream := lz4.NewReader(r)
	tarReader := tar.NewReader(uncompressedStream)
	for true {
		header, err := tarReader.Next()

		if err == io.EOF {
			break
		}
		if err != nil {
			return err;
		}

		switch header.Typeflag {
		case tar.TypeDir:
			_=os.MkdirAll(directory + "/" + header.Name, 0755)
		case tar.TypeReg:
			outFile, err := os.Create(directory + "/" + header.Name)
			if err != nil {
				return err;
			}
			if _, err := io.Copy(outFile, tarReader); err != nil {
				return err;
			}
			outFile.Close()

		default:
			return err;
		}

	}

	return err;
}

//Modified from archiver.TarLz4.Make(...), because that implementation's compression rate is too low: a 45MB is reduced to 14MB, where tar+lz4 can reduce it to 3MB.
//@param excluedExts such as []string{".obj"}
func  Make(tarlz4Path string, filePaths []string, transformMap map[string]string, excludedExts []string) error {
	tmpFile := tarlz4Path + ".tmp";
	out, err := os.Create(tmpFile)
	if err != nil {
		Warnf("error creating %s: %v", tarlz4Path, err)
		return err;
	}
	defer out.Close()

	tarWriter := tar.NewWriter(out)
	tarball(filePaths, tarWriter, tmpFile, transformMap, excludedExts)
	tarWriter.Close()
	defer  os.Remove(tmpFile)

	out, err = os.Create(tarlz4Path )
	lz4Writer := lz4.NewWriter(out)
	lz4Writer.NoChecksum = true;
	defer lz4Writer.Close()
	reader, err := os.Open(tmpFile)
	defer reader.Close()
	if _, err := io.Copy(lz4Writer, reader); err != nil {
		return err;
	}

	return nil;
}

// tarball writes all files listed in filePaths into tarWriter, which is
// writing into a file located at dest.
func tarball(filePaths []string, tarWriter *tar.Writer, dest string, transformMap map[string]string, excludedExt []string) error {
	for _, fpath := range filePaths {
		err := tarFile(tarWriter, fpath, dest, transformMap, excludedExt )
		if err != nil {
			return err
		}
	}
	return nil
}

// tarFile writes the file at source into tarWriter. It does so
// recursively for directories.
func tarFile(tarWriter *tar.Writer, source, dest string, transformMap map[string]string, excludedExt []string) error {
	sourceInfo, err := os.Stat(source)
	if err != nil {
		return fmt.Errorf("%s: stat: %v", source, err)
	}

	var baseDir string
	if sourceInfo.IsDir() {
		baseDir = filepath.Base(source)
		if(transformMap != nil) {
			//Debug("baseDir:", baseDir, ". source: ", source)
			if val, ok := transformMap[baseDir]; ok {
				baseDir = val;
			}
		}
		//if(baseDir == "1"){baseDir = "names"}
	}


	return filepath.Walk(source, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return fmt.Errorf("error walking to %s: %v", path, err)
		}
		if(excludedExt != nil) {
			for _, ext := range excludedExt {
				if (strings.HasSuffix(path, ext)) {
					//fmt.Printf("Skip tar for file %s\n", path)
					return nil;
				}
			}
		}
		header, err := tar.FileInfoHeader(info, path)
		if err != nil {
			return fmt.Errorf("%s: making header: %v", path, err)
		}

		if baseDir != "" {
			header.Name = filepath.Join(baseDir, strings.TrimPrefix(path, source))
			//Debug("path:", path, "; source: ", source, ";base:", baseDir, "; trimmed: ", strings.TrimPrefix(path, source), "; ret: ", header.Name)
		}
		//Debug("header.name is " , header.Name, "; dest is ", dest)
		if header.Name == dest {
			// our new tar file is inside the directory being archived; skip it
			return nil
		}

		if info.IsDir() {
			header.Name += "/"
		}

		//name: objects/57/fe/c9/b95ec0e086f71fedc6f1f3c3555a6dc572b3255a354b066910.dat, B:objects, source:input/3/objects, path:input/3/objects/57/fe/c9/b95ec0e086f71fedc6f1f3c3555a6dc572b3255a354b066910.dat
		//Debugf("header.name is %s, B:%s, source:%s, path:%s", header.Name, baseDir, source, path)
		err = tarWriter.WriteHeader(header)
		if err != nil {
			return fmt.Errorf("%s: writing header: %v", path, err)
		}

		if info.IsDir() {
			return nil
		}

		if header.Typeflag == tar.TypeReg {
			file, err := os.Open(path)
			if err != nil {
				return fmt.Errorf("%s: open: %v", path, err)
			}
			defer file.Close()

			_, err = io.CopyN(tarWriter, file, info.Size())
			if err != nil && err != io.EOF {
				return fmt.Errorf("%s: copying contents: %v", path, err)
			}
		}
		return nil
	})
}

func CompressLz4(fileName string, outputFile string) error {
	out, err := os.Create(outputFile)
	if err != nil {
		return err
	}
	defer out.Close()

	lz4Writer := lz4.NewWriter(out)
	//lz4Writer.NoChecksum = true;
	defer lz4Writer.Close()
	reader, err := os.Open(fileName)
	if err != nil {
		return err
	}
	defer reader.Close()
	if _, err := io.Copy(lz4Writer, reader); err != nil {
		return err
	}
	return nil
}

func DecompressLz4(fileName string, outputFile string) error {
	fileName = filepath.Clean(fileName)
	if(!FileExists(fileName)){
		Warn("To decompress, but file does not exist: ", fileName)
		return errors.New("file does not exist: " + fileName)
	}

	r, err := os.Open(fileName)
	if err != nil {
		return err
	}
	defer r.Close()
	lz4Reader := lz4.NewReader(r)
	//lz4Reader.NoChecksum = true;
	//defer lz4Reader.Close()
	writer, err := os.Create(outputFile)
	if err != nil {
		return err
	}
	defer writer.Close()
	if _, err := io.Copy(writer, lz4Reader); err != nil {
		return err
	}
	return nil
}

// https://github.com/lz4/lz4
func compressLz4Cmd(fileName string, outputFile string) error {
	_, err := RunCommand("lz4", []string{fileName, outputFile});
	return err;
}

// https://github.com/lz4/lz4
func decompressLz4Cmd(fileName string, outputFile string) error {
	_, err := RunCommand("lz4", []string{"-d", fileName, outputFile});
	return err;
}
