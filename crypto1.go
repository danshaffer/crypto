// crypto1.go
package main

import (
	"crypto/aes"
	"encoding/base64"
	"encoding/hex"
	"io/ioutil"
	"strings"
)

func HexToBase64(input string) string {
	byte_arr, _ := hex.DecodeString(input)
	return base64.StdEncoding.EncodeToString(byte_arr)
}

func FixedXOR(input1, input2 string) string {
	bytes1, _ := hex.DecodeString(input1)
	bytes2, _ := hex.DecodeString(input2)
	out := make([]byte, len(bytes1))
	for i := 0; i < len(bytes1); i++ {
		out[i] = bytes1[i] ^ bytes2[i]
	}
	return hex.EncodeToString(out)
}

func GuessKey(input string) (key_b uint8, score_b int, str_b string) {
	input_bytes, _ := hex.DecodeString(input)
	return GuessKeyBytes(input_bytes)
}

func GuessKeyBytes(input_bytes []byte) (key_b uint8, score_b int, str_b string) {
	best := ""
	best_score := -1
	best_key := uint8(0)
	for key := uint8(0); key < uint8(255); key++ {
		attempt := make([]byte, len(input_bytes))
		for i := 0; i < len(input_bytes); i++ {
			attempt[i] = input_bytes[i] ^ key
		}
		attempt_str := string(attempt)
		freq := make(map[string]int)
		for _, c := range strings.ToLower(attempt_str) {
			freq[string(c)] += 1
		}
		score := 0
		score += freq["e"]
		score += freq["t"]
		score += freq["a"]
		score += freq["o"]
		score += freq["i"]
		score += freq["n"]
		score += freq[" "]
		if score > best_score {
			best_score = score
			best = attempt_str
			best_key = key
		}
	}
	return best_key, best_score, best
}

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func GuessWhich(filename string) (line int, result string) {
	dat, err := ioutil.ReadFile(filename)
	check(err)
	lines := strings.Split(string(dat), "\n")
	best_line_num := -1
	best_score := -1
	best_result := ""
	for line_num, content := range lines {
		_, score, decr := GuessKey(content)
		if score > best_score {
			best_line_num = line_num
			best_score = score
			best_result = decr
		}
	}
	return best_line_num, best_result
}

func RepeatingKeyXOR(data string, key string) string {
	data_hex := []byte(data)
	key_hex := []byte(key)
	key_len := len(key_hex)
	result := []byte{}
	for i, b := range data_hex {
		relevant_key := key_hex[i%key_len]
		result = append(result, b^relevant_key)
	}
	return hex.EncodeToString(result)
}

func GetBit(b byte, which uint) bool {
	return ((b>>which)&byte(1) == byte(1))
}

func Hamming(s1 string, s2 string) int {
	b1 := []byte(s1)
	b2 := []byte(s2)
	return HammingBytes(b1, b2)
}

func HammingBytes(b1 []byte, b2 []byte) int {
	dist := 0
	for i, b := range b1 {
		c := b2[i]
		for j := uint(0); j < 8; j++ {
			if GetBit(b, j) != GetBit(c, j) {
				dist++
			}
		}
	}
	return dist
}

func BreakRepeatingXOR(filename string) (key string, result string) {
	dat, err := ioutil.ReadFile(filename)
	check(err)
	lines := strings.Split(string(dat), "\n")
	full_text := strings.Join(lines, "")
	barr, berr := base64.StdEncoding.DecodeString(full_text)
	check(berr)
	best_size := -1
	best_dist := float32(1000)
	for keysize := 2; keysize <= 40; keysize++ {
		b1 := barr[:keysize]
		b2 := barr[keysize : 2*keysize]
		b3 := barr[2*keysize : 3*keysize]
		b4 := barr[3*keysize : 4*keysize]
		avg_dist := float32(HammingBytes(b1, b2) + HammingBytes(b2, b3) + HammingBytes(b3, b4) + HammingBytes(b1, b3) + HammingBytes(b1, b4) + HammingBytes(b2, b4))
		avg_dist /= 6.0
		avg_dist /= float32(keysize)
		if avg_dist < best_dist {
			best_dist = avg_dist
			best_size = keysize
		}
	}
	transposes := make([][]byte, best_size)
	for i, b := range barr {
		transposes[i%best_size] = append(transposes[i%best_size], b)
	}
	full_key := make([]uint8, 0)
	for _, bs := range transposes {
		key, _, _ := GuessKeyBytes(bs)
		full_key = append(full_key, key)
	}
	key_str := string([]byte(full_key))
	results_b, _ := hex.DecodeString(RepeatingKeyXOR(string(barr), key_str))
	return key_str, string(results_b)
}

func DecryptAes(filename string, key string) string {
	dat, err := ioutil.ReadFile(filename)
	check(err)
	lines := strings.Split(string(dat), "\n")
	plaintext := strings.Join(lines, "")
	barr, berr := base64.StdEncoding.DecodeString(plaintext)
	check(berr)
	ciphertext := make([]byte, len(barr))
	result := ciphertext

	for len(barr) > 0 {
		cipher, cerr := aes.NewCipher([]byte(key))
		check(cerr)
		cipher.Decrypt(ciphertext, barr)
		barr = barr[16:]
		ciphertext = ciphertext[16:]
	}
	return string(result)
}

func main() {

}
