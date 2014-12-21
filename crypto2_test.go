// crypto2_test.go
package main

import (
	"encoding/base64"
	"io/ioutil"
	"strings"
	"testing"
)

func TestPKCSPadding(t *testing.T) {
	want := "YELLOW SUBMARINE\x04\x04\x04\x04"
	actual := PKCSPadding("YELLOW SUBMARINE", 20)
	if actual != want {
		t.Errorf("PKCSPadding() = %s, want %s", actual, want)
	}
}

func TestDecryptCbc(t *testing.T) {
	dat, err := ioutil.ReadFile("/home/dan/Documents/Programming/Crypto/set2ch10.txt")
	check(err)
	lines := strings.Split(string(dat), "\n")
	input := strings.Join(lines, "")
	barr, berr := base64.StdEncoding.DecodeString(input)
	check(berr)
	key := []byte("YELLOW SUBMARINE")
	iv := make([]byte, len(key))
	for idx, _ := range iv {
		iv[idx] = 0
	}
	result := DecryptCbc(barr, key, iv)
	expected := "I'm back and I'm ringin' the bell"
	if result[:len(expected)] != expected {
		t.Errorf("DecryptCbc() = %s, want %s", result, expected)
	}
}
