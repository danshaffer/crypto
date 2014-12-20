// crypto1_test.go
package main

import (
	"io/ioutil"
	"strings"
	"testing"
)

func TestHexToBase64(t *testing.T) {
	want := "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
	in := "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
	if HexToBase64(in) != want {
		t.Errorf("HextToBase64() = %s, want %s", HexToBase64(in), want)
	}
}

func TestFixedXOR(t *testing.T) {
	want := "746865206b696420646f6e277420706c6179"
	in1 := "1c0111001f010100061a024b53535009181c"
	in2 := "686974207468652062756c6c277320657965"
	result := FixedXOR(in1, in2)
	if result != want {
		t.Errorf("FixedXOR() = %s, want %s", result, want)
	}
}

func TestGuessKey(t *testing.T) {
	wanted_score := 19
	wanted_key := uint8(88)
	wanted_str := "Cooking MC's like a pound of bacon"
	input := "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
	result_key, result_score, result_str := GuessKey(input)
	if result_key != wanted_key {
		t.Errorf("GuessKey() key = %d, want %d", result_key, wanted_key)
	}
	if result_score != wanted_score {
		t.Errorf("GuessKey() score = %d, want %d", result_score, wanted_score)
	}
	if result_str != wanted_str {
		t.Errorf("GuessKey() str = '%s', want '%s'", result_str, wanted_str)
	}
}

func TestGuessWhich(t *testing.T) {
	_, result := GuessWhich("/home/dan/Documents/Programming/Crypto/set1ch4.txt")
	expected := "Now that the party is jumping\n"
	if result != expected {
		t.Errorf("GuessWhich() result = '%s', want '%s'", result, expected)
	}
}

func TestRepeatingKeyXOR(t *testing.T) {
	plain := "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
	key := "ICE"
	encoded := RepeatingKeyXOR(plain, key)
	expected := "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
	if encoded != expected {
		t.Errorf("GuessWhich() result = '%s', want '%s'", encoded, expected)
	}
}

func TestGetBit(t *testing.T) {
	if !GetBit(byte(1), 0) {
		t.Errorf("GetBit(1, 0) failed")
	}
	if GetBit(byte(1), 1) {
		t.Errorf("GetBit(1, 1) failed")
	}
	if GetBit(byte(2), 0) {
		t.Errorf("GetBit(2, 0) failed")
	}
	if !GetBit(byte(2), 1) {
		t.Errorf("GetBit(2, 1) failed")
	}
}

func TestHamming(t *testing.T) {
	result := Hamming("this is a test", "wokka wokka!!!")
	if result != 37 {
		t.Errorf("Hamming() result = %d, want 37", result)
	}
}

func TestBreakRepeatingXOR(t *testing.T) {
	key, _ := BreakRepeatingXOR("/home/dan/Documents/Programming/Crypto/set1ch6.txt")
	wanted := "Terminator X: Bring the noise"
	if key != wanted {
		t.Errorf("BreakRepeatingXOR() key was '%s', wanted '%s'", key, wanted)
	}
}

func TestDecryptAes(t *testing.T) {
	wanted := "I'm back and"
	actual := DecryptAes("/home/dan/Documents/Programming/Crypto/set1ch7.txt", "YELLOW SUBMARINE")
	if wanted != actual[:len(wanted)] {
		t.Error("DecryptAes result was incorrect")
	}
}

func TestFindAes(t *testing.T) {
	dat, err := ioutil.ReadFile("/home/dan/Documents/Programming/Crypto/set1ch8.txt")
	check(err)
	lines := strings.Split(string(dat), "\n")
	for idx, line := range lines {
		if num_dupes := IsAes(line); num_dupes > 0 && idx != 132 {
			t.Errorf("Found %d dupes in line %d", num_dupes, idx)
		}
	}
}
