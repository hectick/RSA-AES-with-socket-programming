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
	/* 서버 연결 정보 */
	serverName := "127.0.0.1"
	serverPort := "12345"
	conn, _ := net.Dial("tcp", serverName+":"+serverPort) //tcp 프로토콜 사용. 서버의 IP와 포트번호를 설정해줌. 설정된 목적지로 데이터를 전송함.
	localAddr := conn.LocalAddr().(*net.TCPAddr)
	fmt.Printf("## Client port number : %d ##\n\n", localAddr.Port)

	/* 서버로부터 공개키를 받는 부분 */
	buffer := make([]byte, 2048)                               //버퍼를 만들고 서버로부터 메세지가 오기를 기다림
	conn.Read(buffer)                                          //버퍼안에 내용물이 들어오면 메세지를 읽음
	sDec, _ := base64.StdEncoding.DecodeString(string(buffer)) //디코딩해서 공개키를 저장
	publicKey := &rsa.PublicKey{}
	json.Unmarshal(sDec, publicKey) //공개키 형식 다듬기
	fmt.Printf("## Receive public key from Server ##\n")
	fmt.Printf("[Public key] %x\n\n", publicKey) //공개키 프린트

	/* 대칭키 생성 */
	fmt.Printf("Write 16byte for creating symmetric key >> ")
	symmetricKey, _ := bufio.NewReader(os.Stdin).ReadString('\n') //대칭키를 입력해줌
	symmetricKey = strings.TrimSpace(symmetricKey)
	for len(symmetricKey) != 16 { //대칭키가 16바이트가 아니면 다시 입력하도록 함
		fmt.Printf("Retry : Write 16byte for creating symmetric key >> ")
		symmetricKey, _ = bufio.NewReader(os.Stdin).ReadString('\n')
		symmetricKey = strings.TrimSpace(symmetricKey)
	}

	/* 대칭키를 공개키로 암호화 - 평문을 공개키 암호화 코드를 구글링으로 찾음*/
	ciphertext, err := rsa.EncryptPKCS1v15(
		rand.Reader,
		publicKey,            //공개키를 이용해서
		[]byte(symmetricKey), //대칭키를 암호화
	)
	if err != nil {
		os.Exit(0)
	}

	/* 대칭키 전송 */
	sendMsg := base64.StdEncoding.EncodeToString(ciphertext) //인코딩
	fmt.Printf("\n## Send symmetric key to Server \n")
	fmt.Printf("[Symmetric key] %s\n", symmetricKey)
	fmt.Printf("[Ciphertext] %x\n\n", ciphertext)
	conn.Write([]byte(sendMsg)) //서버에게 대칭키 전송

	/* AES 대칭키 암호화 블록 생성 */
	block, _ := NewAesCipher([]byte(symmetricKey)) //대칭키 암호화에 사용할 블록을 생성해줌

	/* ctrl+c를 눌러서 종료할때 서버에게 연결 닫으라고 알려주는 부분 */
	go func() { //go routine 사용. 프로그램을 실행하다가 언제든 ctrl+c를 누르면 서버에게 종료 메세지가 송신되도록 동작.
		signals := make(chan os.Signal, 1)
		signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
		<-signals
		fmt.Println("## Disconnected ##")
		ciphertext := block.Encrypt("0") //0은 종료를 의미
		sendMsg := base64.StdEncoding.EncodeToString(ciphertext)
		conn.Write([]byte(sendMsg))
		conn.Close()
		os.Exit(0)
	}()

	/*채팅 시작*/
	go receive(conn)
	go send(conn)
	go handler(block)
	for {
		input, _ := bufio.NewReader(os.Stdin).ReadString('\n') //클라이언트 쪽에서 채팅을 입력
		input = strings.TrimSpace(input)
		input = "1" + input
		inputChannel <- input
	}
}

func handler(block *AESCipher) {
	for {
		select {
		case buffer := <-receiveChannel: // receive 가 들어온 경우엔? 출력하기
			ciphertextFromServer, _ := base64.StdEncoding.DecodeString(string(buffer)) //디코딩
			message := block.Decrypt(ciphertextFromServer)                             //서버로부터 받은 암호문을 대칭키로 복호화
			fmt.Printf("## Receive From Server ##\n")
			fmt.Printf("[Ciphertext] %x\n", ciphertextFromServer)
			fmt.Printf("[message] %s\n\n", message)
		case input := <-inputChannel: // 입력값이 들어온 경우엔? send 하기
			ciphertext := block.Encrypt(input)                       //채팅을 대칭키 암호화
			sendMsg := base64.StdEncoding.EncodeToString(ciphertext) //인코딩
			fmt.Printf("## Send to Server ##\n")
			fmt.Printf("[message] %s\n", input[1:])
			fmt.Printf("[Ciphertext] %x\n\n", ciphertext)
			sendChannel <- []byte(sendMsg) //send channel 로 전송
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

	// Make the cipher text a byte array of size BlockSize + the length of the message
	encryptByteArray := make([]byte, aes.BlockSize+len(s))

	// The IV needs to be unique, but not secure. Therefore, it's common to include it at the beginning of the ciphertext.
	iv := encryptByteArray[:aes.BlockSize]

	io.ReadFull(rand.Reader, iv) //rand.Reader 에서 난수를 생성해서 iv에 넣기

	// Encrypt the data
	// iv는 블록의 블록 크기와 길이가 같아야 함
	// 블록암호 : 평문의 동일 블록들이 하나의 메시지에서 동일한 암호문으로 되지 않도록 하기 위해 이전 암호 블록의 암호문을 다음 블록에 순서대로 적용
	stream := cipher.NewCFBEncrypter(a.block, iv) //iv ==block size 여야 함
	stream.XORKeyStream(encryptByteArray[aes.BlockSize:], byteString)

	return encryptByteArray
}

func (a *AESCipher) Decrypt(byteString []byte) string { //대칭키 복호화 코드

	decryptByteArray := make([]byte, len(byteString))
	iv := byteString[:aes.BlockSize] //첫번째 암호문에 대해서는 IV(Initial Vector)가 암호문 대신 사용

	//Decrypt the data
	stream := cipher.NewCFBDecrypter(a.block, iv)
	stream.XORKeyStream(decryptByteArray, byteString[aes.BlockSize:])

	return string(decryptByteArray)
}
