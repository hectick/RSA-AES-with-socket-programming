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
	go func() {
		signals := make(chan os.Signal, 1)
		signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
		<-signals
		os.Exit(0)
	}()

	/* 서버 정보 */
	serverPort := "12345"

	listener, _ := net.Listen("tcp", ":"+serverPort)
	fmt.Printf("## Server port number : %s ##\n\n", serverPort)

	/* 공개키 암호화 알고리즘 - 개인키,공개키(비대칭키)를 생성 */
	privateKey, err := rsa.GenerateKey(rand.Reader, 512)
	if err != nil {
		fmt.Println(err)
		return
	}
	publicKey := &privateKey.PublicKey
	fmt.Printf("## RSA private key and public key is generated ##\n\n")

	for {
		/* 클라이언트 연결 */
		conn, err := listener.Accept()
		if err != nil {
			continue
		}

		/*클라이언트에 공개키를 보내는 부분*/
		pubInJason, err := json.Marshal(publicKey)
		pub2 := &rsa.PublicKey{}
		err = json.Unmarshal(pubInJason, pub2)      
		sendMsg := base64.StdEncoding.EncodeToString(pubInJason) 
		fmt.Printf("## Send public key to Client %s ##\n", conn.RemoteAddr().String())
		fmt.Printf("[Public key] %x\n\n", publicKey)
		conn.Write([]byte(sendMsg)) 

		/*클라이언트에서 응답으로 대칭키가 오는 부분*/
		buffer := make([]byte, 2048)
		conn.Read(buffer) 
		ciphertext, _ := base64.StdEncoding.DecodeString(string(buffer))
		/*암호화된 대칭키를 개인 키로 복호화 */
		plaintext, err := rsa.DecryptPKCS1v15( 
			rand.Reader,
			privateKey, 
			ciphertext,
		)
		symmetricKey := string(plaintext)
		fmt.Printf("## Receive symmetric key from Client %s ##\n", conn.RemoteAddr().String())
		fmt.Printf("[Ciphertext] %x\n", ciphertext)
		fmt.Printf("[symmetric key] %s\n\n", symmetricKey)

		/* 대칭키 암호화에 사용할 대칭키 블록 생성 */
		block, _ := NewAesCipher([]byte(symmetricKey))

		/* 메세지를 받는 부분 */
		go func() {
			for {
				buffer := make([]byte, 2048)
				_, err := conn.Read(buffer)
				if err != nil {
					continue
				}
				fmt.Printf("## Receive from Client %s ##\n", conn.RemoteAddr().String())
				ciphertextFromClient, _ := base64.StdEncoding.DecodeString(string(buffer))
				message := block.Decrypt(ciphertextFromClient)
				option := message[:1]
				if option == "1" { //메세지의 맨 앞의 옵션이 1이면 채팅이고 아니면 종료하도록 함
					fmt.Printf("[Ciphertext] %x\n", ciphertextFromClient)
					fmt.Printf("[message] %s\n\n", message[1:])
				} else { //종료
					fmt.Printf("## Client %s disconnected ##\n\n", conn.RemoteAddr().String())
					conn.Close()
					break
				}
			}
		}()

		/* 메세지를 보내는 부분*/
		for {
			input, _ := bufio.NewReader(os.Stdin).ReadString('\n')
			input = strings.TrimSpace(input)
			ciphertext := block.Encrypt(input)
			sendMsg := base64.StdEncoding.EncodeToString(ciphertext)

			conn.Write([]byte(sendMsg)) //송신
			fmt.Printf("## Send to Client %s ##\n", conn.RemoteAddr().String())
			fmt.Printf("[message] %s\n", input)
			fmt.Printf("[Ciphertext] %x\n\n", ciphertext)
		}
	}
}

/* 대칭키 암호화, 복호화 코드 */
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
