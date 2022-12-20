package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
)

func main() {
	/* 서버 연결 정보 */
	serverName := "127.0.0.1"
	serverPort := "12345"
	conn, _ := net.Dial("tcp", serverName+":"+serverPort)
	localAddr := conn.LocalAddr().(*net.TCPAddr)
	fmt.Printf("## Client port number : %d ##\n\n", localAddr.Port)

	/* 서버로부터 공개키를 받는 부분 */
	buffer := make([]byte, 2048)
	conn.Read(buffer)
	sDec, _ := base64.StdEncoding.DecodeString(string(buffer))
	publicKey := &rsa.PublicKey{}
	json.Unmarshal(sDec, publicKey)
	fmt.Printf("## Receive public key from Server ##\n")
	fmt.Printf("[Public key] %x\n\n", publicKey)

	/* 대칭키 생성 */
	fmt.Printf("Write 16byte for creating symmetric key >> ")
	symmetricKey, _ := bufio.NewReader(os.Stdin).ReadString('\n') 
	symmetricKey = strings.TrimSpace(symmetricKey)
	for len(symmetricKey) != 16 { 
		fmt.Printf("Retry : Write 16byte for creating symmetric key >> ")
		symmetricKey, _ = bufio.NewReader(os.Stdin).ReadString('\n')
		symmetricKey = strings.TrimSpace(symmetricKey)
	}

	/* 대칭키를 공개키로 암호화 */
	ciphertext, err := rsa.EncryptPKCS1v15(
		rand.Reader,
		publicKey,            
		[]byte(symmetricKey), 
	)
	if err != nil {
		os.Exit(0)
	}

	/* 대칭키 전송 */
	sendMsg := base64.StdEncoding.EncodeToString(ciphertext) 
	fmt.Printf("\n## Send symmetric key to Server \n")
	fmt.Printf("[Symmetric key] %s\n", symmetricKey)
	fmt.Printf("[Ciphertext] %x\n\n", ciphertext)
	conn.Write([]byte(sendMsg)) 

	/* AES 대칭키 암호화 블록 생성 */
	block, _ := NewAesCipher([]byte(symmetricKey)) 

	go func() {
		signals := make(chan os.Signal, 1)
		signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
		<-signals
		fmt.Println("## Disconnected ##")
		ciphertext := block.Encrypt("0")
		sendMsg := base64.StdEncoding.EncodeToString(ciphertext)
		conn.Write([]byte(sendMsg))
		conn.Close()
		os.Exit(0)
	}()

	/* 서버에서 메세지를 받는 부분 */
	go func() { 
		for {
			buffer := make([]byte, 2048)
			_, err := conn.Read(buffer) 
			if err != nil {
				continue
			}
			ciphertextFromServer, _ := base64.StdEncoding.DecodeString(string(buffer)) 
			message := block.Decrypt(ciphertextFromServer)  
			fmt.Printf("## Receive From Server ##\n")
			fmt.Printf("[Ciphertext] %x\n", ciphertextFromServer)
			fmt.Printf("[message] %s\n\n", message)
		}
	}()

	/*클라이언트가 서버에게 메세지를 보내는 부분*/
	for {
		input, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		input = strings.TrimSpace(input)
		input = "1" + input
		ciphertext := block.Encrypt(input) 
		sendMsg := base64.StdEncoding.EncodeToString(ciphertext) 

		fmt.Printf("## Send to Server ##\n")
		fmt.Printf("[message] %s\n", input[1:])
		fmt.Printf("[Ciphertext] %x\n\n", ciphertext)
		conn.Write([]byte(sendMsg)) 
	}
}

/* 대칭키 암호화 복호화 코드 */
type AESCipher struct {
	block cipher.Block
}

func NewAesCipher(key []byte) (*AESCipher, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return &AESCipher{block}, nil
}

func (a *AESCipher) Encrypt(s string) []byte {
	byteString := []byte(s)
	encryptByteArray := make([]byte, aes.BlockSize+len(s))

	iv := encryptByteArray[:aes.BlockSize]
	io.ReadFull(rand.Reader, iv)

	stream := cipher.NewCFBEncrypter(a.block, iv) 
	stream.XORKeyStream(encryptByteArray[aes.BlockSize:], byteString)

	return encryptByteArray
}

func (a *AESCipher) Decrypt(byteString []byte) string {

	decryptByteArray := make([]byte, len(byteString))
	iv := byteString[:aes.BlockSize]

	stream := cipher.NewCFBDecrypter(a.block, iv)
	stream.XORKeyStream(decryptByteArray, byteString[aes.BlockSize:])

	return string(decryptByteArray)
}
