package loggregator_test

import (
	"io/ioutil"
	"log"
)

//go:generate go get github.com/loggregator/go-bindata/...
//go:generate scripts/generate-test-certs
//go:generate go-bindata -nocompress -o bindata_test.go -pkg loggregator_test -prefix test-certs/ test-certs/
//go:generate rm -rf test-certs


func fixture(filename string) string {
	contents := MustAsset(filename)

	tmpfile, err := ioutil.TempFile("", "")
	if err != nil {
		log.Fatal(err)
	}

	if _, err := tmpfile.Write(contents); err != nil {
		log.Fatal(err)
	}
	if err := tmpfile.Close(); err != nil {
		log.Fatal(err)
	}

	return tmpfile.Name()
}
