/*
Copyright 2020 The Flux CD contributors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package testserver

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha1"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
)

func NewTempArtifactServer() (*ArtifactServer, error) {
	server, err := NewTempHTTPServer()
	if err != nil {
		return nil, err
	}
	artifact := &ArtifactServer{server}
	return artifact, nil
}

type ArtifactServer struct {
	*HTTPServer
}

type File struct {
	Name string
	Body string
}

// ArtifactFromBytes creates a tar.gz artifact from the given files and
// returns the file name of the artifact.
func (s *ArtifactServer) ArtifactFromBytes(files []File) (string, error) {
	fileName := calculateArtifactName(files)
	filePath := filepath.Join(s.docroot, fileName)
	gzFile, err := os.Create(filePath)
	if err != nil {
		return "", err
	}
	defer gzFile.Close()

	gw := gzip.NewWriter(gzFile)
	defer gw.Close()

	tw := tar.NewWriter(gw)
	defer tw.Close()

	for _, file := range files {
		hdr := &tar.Header{
			Name: file.Name,
			Mode: 0600,
			Size: int64(len(file.Body)),
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return "", err
		}
		if _, err := tw.Write([]byte(file.Body)); err != nil {
			return "", err
		}
	}
	return fileName, nil
}

// URLForFile returns the URL the given file path can be reached at or
// an error if the server has not been started.
func (s *ArtifactServer) URLForFile(file string) (string, error) {
	if s.URL() == "" {
		return "", errors.New("server must be started to be able to determine the URL of the given file")
	}
	return path.Join(s.URL(), file), nil
}

func calculateArtifactName(files []File) string {
	h := sha1.New()
	for _, f := range files {
		h.Write([]byte(f.Body))
	}
	return fmt.Sprintf("%x.tar.gz", h.Sum(nil))
}
