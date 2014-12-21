// crypto2.go
package main

import (
	"crypto/aes"
	"crypto/rand"
)

func PKCSPadding(key string, length int) string {
	key_bytes := []byte(key)
	padding := length - len(key_bytes)
	padded_key := make([]byte, length)
	for i := range padded_key {
		if i < len(key_bytes) {
			padded_key[i] = key_bytes[i]
		} else {
			padded_key[i] = byte(padding)
		}
	}
	return string(padded_key)
}

func DecryptBlock(input []byte, key []byte, iv []byte) []byte {
	result := make([]byte, len(key))
	cipher, cerr := aes.NewCipher(key)
	check(cerr)
	cipher.Decrypt(result, input)
	for idx, val := range result {
		result[idx] = val ^ iv[idx]
	}
	return result
}

func DecryptCbc(input []byte, key []byte, iv []byte) string {
	input_size := len(input)
	result := make([]byte, input_size)
	offset := 0
	for offset < len(input) {
		sub_result := DecryptBlock(input[offset:offset+len(key)], key, iv)
		for idx, b := range sub_result {
			result[offset+idx] = b
		}
		iv = input[offset : offset+len(key)]
		offset += len(key)
	}
	return string(result)
}

// RandomKey returns a random 16-byte AES key
func RandomKey() []byte {
	result := make([]byte, 16)
	_, err := rand.Read(result)
	check(err)
	return result
}
