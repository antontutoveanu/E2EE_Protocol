package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"time"
)

func main() {

	MASTER_KEY := [32]byte{48, 124, 87, 188, 181, 244, 165, 54, 249, 79, 112, 76, 201, 137, 208, 20, 14, 79, 102, 56, 19, 51, 125, 166, 52, 49, 19, 37, 194, 15, 99, 168}
	PRIVATE_KEY, err := ioutil.ReadFile("../data/privatekey.txt") // read private key from file
	if err != nil {
		fmt.Print(err)
	}
	//========================================================================================//
	// SERVER SIDE PROTOCOL TEST 2
	//========================================================================================//
	// open plaintext data file and read into byte array
	PLAINTEXT, err := ioutil.ReadFile("../data/plaintext.txt")
	if err != nil {
		fmt.Print(err)
	}
	// encrypt plaintext data with master key
	CIPHERTEXT := AES256GCM_ENCRYPT(MASTER_KEY, PLAINTEXT)
	// save ciphertext data to file as base64 string
	outfile, err := os.Create("../data/ciphertext.txt")
	if err != nil {
		log.Fatal(err)
	}
	defer outfile.Close()
	// bytes to base64
	CIPHERTEXT_base64 := base64.StdEncoding.EncodeToString(CIPHERTEXT)
	_, err1 := outfile.WriteString(CIPHERTEXT_base64)
	if err1 != nil {
		log.Fatal(err1)
	}
	//========================================================================================//
	// STEP 2: SESSION KEY RSA DECRYPT
	//========================================================================================//
	// read c values from client into array
	c_hex_array := make([]string, 0)
	// open client_c.txt file
	file, err := os.Open("../data/client_c.txt")
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()
	// read hex strings into array
	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanWords)
	for scanner.Scan() {
		c_hex := scanner.Text()
		c_hex_array = append(c_hex_array, c_hex)
	}
	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}
	// for each c value from client (100 values)
	time_sum2 := 0
	SESSION_KEY_base64_array := make([]string, 0)
	for i := 0; i < 100; i++ { // average of 100 test runs

		// start timer
		start := time.Now()

		//-------------------------------------------------------
		// get c from c_base64_array and convert to byte array
		c_byte, _ := hex.DecodeString(c_hex_array[i])
		var c [768]byte
		copy(c[:], c_byte)
		// 2. (Session) Key Decapsulation
		SESSION_KEY, err := decryptRSA(c_byte, PRIVATE_KEY)
		if err != nil {
			log.Fatal(err)
		}
		// convert session key to base64 string
		SESSION_KEY_base64 := string(SESSION_KEY[:])
		//-------------------------------------------------------

		// end timer
		time2 := time.Since(start)

		// add to time sum
		time_sum2 += int(time2.Microseconds()) // convert to microseconds

		// append to array
		SESSION_KEY_base64_array = append(SESSION_KEY_base64_array, SESSION_KEY_base64)
	}
	// calculate average time for step 2
	avg_time2 := float64(time_sum2) / 100.0
	fmt.Println("Average time step 2: ", avg_time2, " microseconds")

	// write session keys to server_ss.txt
	outfile2, err := os.Create("../data/server_ss.txt")
	if err != nil {
		log.Fatal(err)
	}
	defer outfile2.Close()
	// write to file
	for i := 0; i < 100; i++ {
		_, err1 := outfile2.WriteString(SESSION_KEY_base64_array[i] + "\n")
		if err1 != nil {
			log.Fatal(err1)
		}
	}

	time_sum3 := 0
	ENC_MASTER_KEY_base64_array := make([]string, 0)
	for i := 0; i < 100; i++ { // average of 100 test runs

		// start timer
		start := time.Now()

		//-------------------------------------------------------
		// decode session key into byte array
		SESSION_KEY_byte, _ := base64.StdEncoding.DecodeString(SESSION_KEY_base64_array[i])
		var SESSION_KEY [32]byte
		copy(SESSION_KEY[:], SESSION_KEY_byte)
		// 3. Encrypt MASTER_KEY with SESSION_KEY
		ENC_MASTER_KEY := AES256GCM_ENCRYPT(SESSION_KEY, MASTER_KEY[:])
		// convert ENC_MASTER_KEY to base64 string and append to array
		ENC_MASTER_KEY_base64 := base64.StdEncoding.EncodeToString(ENC_MASTER_KEY[:])
		//-------------------------------------------------------

		// end timer
		time3 := time.Since(start)

		// add to time sum
		time_sum3 += int(time3.Microseconds()) // convert to microseconds

		// append to array
		ENC_MASTER_KEY_base64_array = append(ENC_MASTER_KEY_base64_array, ENC_MASTER_KEY_base64)
	}
	// calculate average time for step 3
	avg_time3 := float64(time_sum3) / 100.0
	fmt.Println("Average time step 3: ", avg_time3, " microseconds")

	// add to text file (for client side testing)
	// open server_enc_mk.txt file
	file1, err1 := os.Create("../data/server_enc_mk.txt")
	if err1 != nil {
		log.Fatal(err1)
	}
	defer file1.Close()
	// write to file
	for i := 0; i < 100; i++ {
		_, err1 := file1.WriteString(ENC_MASTER_KEY_base64_array[i] + "\n")
		if err1 != nil {
			log.Fatal(err1)
		}
	}

}

// bytes as input and output
func AES256GCM_ENCRYPT(KEY [32]byte, PLAINTEXT []byte) []byte {

	block, err := aes.NewCipher(KEY[:])
	if err != nil {
		panic(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}
	nonce := make([]byte, gcm.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		panic(err)
	}
	CIPHERTEXT := gcm.Seal(nonce, nonce, []byte(PLAINTEXT), nil)

	return CIPHERTEXT
}

func decryptRSA(ct []byte, privateKeyPemBytes []byte) ([]byte, error) {

	block, _ := pem.Decode(privateKeyPemBytes)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return nil, errors.New("not a private key")
	}

	privKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	plaintext, err := rsa.DecryptOAEP(sha1.New(), rand.Reader, privKey, ct, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
