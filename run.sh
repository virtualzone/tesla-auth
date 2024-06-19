#!/bin/sh
TESLA_CLIENT_ID=77ef77aa-8619-4e12-b742-1afa08dbee0d PUBLIC_KEY_PATH=./test.pem go run `ls *.go | grep -v _test.go`