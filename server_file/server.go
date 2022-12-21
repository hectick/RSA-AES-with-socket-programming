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

var receiveChannel = make(chan []byte)
var inputChannel = make(chan string)
var sendChannel = make(chan []byte)

func main() {
	go func() { //서버 종료 goroutine
		signals := make(chan os.Signal, 1)
		signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
		<-signals
		os.Exit(0)
	}()

	/* 서버 정보 */
	serverPort := "12345" //서버의 포트번호

	listener, _ := net.Listen("tcp", ":"+serverPort) //소켓 열기
	fmt.Printf("## Server port number : %s ##\n\n", serverPort)

	/* 공개키 암호화 알고리즘 - 개인키,공개키(비대칭키)를 생성 - 구글링으로 찾음 */
	privateKey, err := rsa.GenerateKey(rand.Reader, 512) //개인키와 공개키 생성
	if err != nil {
		fmt.Println(err)
		return
	}
	publicKey := &privateKey.PublicKey //개인키 객체 안에 저장되어 있는 공개키를 따로 저장
	fmt.Printf("## RSA private key and public key is generated ##\n\n")

	/* 클라이언트 연결 */
	conn, _ := listener.Accept() //클라이언트로부터 연결 요청 듣기

	/*클라이언트에 공개키를 보내는 부분*/
	pubInJason, err := json.Marshal(publicKey)
	pub2 := &rsa.PublicKey{}
	err = json.Unmarshal(pubInJason, pub2)                   //공개키를 소켓통신을 통해 보낼 수 있도록 형식을 다듬어줌
	sendMsg := base64.StdEncoding.EncodeToString(pubInJason) //인코딩
	fmt.Printf("## Send public key to Client %s ##\n", conn.RemoteAddr().String())
	fmt.Printf("[Public key] %x\n\n", publicKey)
	conn.Write([]byte(sendMsg)) //클라이언트에게 공개키 보냄

	/*클라이언트에서 응답으로 대칭키가 오는 부분*/
	buffer := make([]byte, 2048)
	conn.Read(buffer) //대칭키 읽음
	ciphertext, _ := base64.StdEncoding.DecodeString(string(buffer))
	/*암호화된 대칭키를 개인 키로 복호화 - 개인키 복호화 코드는 구글링으로 찾음*/
	plaintext, err := rsa.DecryptPKCS1v15( //복호화해서 대칭키 추출
		rand.Reader,
		privateKey, // 개인키
		ciphertext,
	)
	symmetricKey := string(plaintext) //대칭키를 string 형식으로 변환
	fmt.Printf("## Receive symmetric key from Client %s ##\n", conn.RemoteAddr().String())
	fmt.Printf("[Ciphertext] %x\n", ciphertext)
	fmt.Printf("[symmetric key] %s\n\n", symmetricKey)
	//응답 끝

	/* 대칭키 암호화에 사용할 대칭키 블록 생성 */
	block, _ := NewAesCipher([]byte(symmetricKey))

	/*채팅 시작*/
	go receive(conn)
	go send(conn)
	go handler(conn, block)

	for {
		input, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		input = strings.TrimSpace(input)
		inputChannel <- input
	}
}

func handler(conn net.Conn, block *AESCipher) {
	for {
		select {
		case buffer := <-receiveChannel: // receive 가 들어온 경우엔? 출력하기
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
				os.Exit(0)
				return
			}
		case input := <-inputChannel: // 입력값이 들어온 경우엔? send 하기
			ciphertext := block.Encrypt(input)                       //채팅을 대칭키 암호화
			sendMsg := base64.StdEncoding.EncodeToString(ciphertext) //인코딩
			fmt.Printf("## Send to Client %s ##\n", conn.RemoteAddr().String())
			fmt.Printf("[message] %s\n", input)
			fmt.Printf("[Ciphertext] %x\n\n", ciphertext)
			sendChannel <- []byte(sendMsg) //send 채널로 전송
		}
	}
}

func receive(conn net.Conn) {
	for {
		buffer := make([]byte, 2048)
		_, err := conn.Read(buffer)
		if err != nil {
			continue
		}
		receiveChannel <- buffer
	}
}

func send(conn net.Conn) {
	for {
		message := <-sendChannel
		conn.Write(message)
	}
}

/*여기서부턴 구글링으로 찾은 대칭키 암호화, 복호화 코드를 약간 변형하였음*/
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

func (a *AESCipher) Encrypt(s string) []byte { //대칭키 암호화 코드
	byteString := []byte(s)
	encryptByteArray := make([]byte, aes.BlockSize+len(s))

	iv := encryptByteArray[:aes.BlockSize]

	io.ReadFull(rand.Reader, iv)

	stream := cipher.NewCFBEncrypter(a.block, iv)
	stream.XORKeyStream(encryptByteArray[aes.BlockSize:], byteString)

	return encryptByteArray
}

func (a *AESCipher) Decrypt(byteString []byte) string { //대칭키 복호화 코드

	decryptByteArray := make([]byte, len(byteString))
	iv := byteString[:aes.BlockSize]

	stream := cipher.NewCFBDecrypter(a.block, iv)
	stream.XORKeyStream(decryptByteArray, byteString[aes.BlockSize:])

	return string(decryptByteArray)
}
