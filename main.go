package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"strings"
	"time"

	"github.com/quic-go/quic-go"
)

const (
	ListenPort = ":443"                             // پورت استاندارد HTTPS برای پنهان‌کاری
	Password   = "SkyShield_v8_Secure_921"          // پسورد اختصاصی شما
)

func main() {
	cert, err := generateSelfSignedCert()
	if err != nil {
		log.Fatal(err)
	}

	tlsConf := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h3"}, // تظاهر به پروتکل HTTP/3
	}

	quicConf := &quic.Config{
		Allow0RTT: true,
		MaxIdleTimeout: 30 * time.Second,
	}

	listener, err := quic.ListenAddr(ListenPort, tlsConf, quicConf)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Submarine Server is Diving on %s... (UDP)\n", ListenPort)

	for {
		conn, err := listener.Accept(context.Background())
		if err != nil {
			continue
		}
		go func(c quic.Connection) {
			for {
				stream, err := c.AcceptStream(context.Background())
				if err != nil {
					return
				}
				go handleSubmarineStream(stream)
			}
		}(conn)
	}
}

func handleSubmarineStream(stream quic.Stream) {
	defer stream.Close()
	
	// لایه دفاعی: اگر در 3 ثانیه پسورد فرستاده نشد، قطع ارتباط
	stream.SetReadDeadline(time.Now().Add(3 * time.Second))

	reader := bufio.NewReader(stream)
	authData, err := reader.ReadString('\n')
	if err != nil {
		return
	}

	parts := strings.Split(strings.TrimSpace(authData), "@")
	if len(parts) != 2 || parts[0] != Password {
		// رفتار سیاه چاله: بدون هیچ پاسخی ارتباط قطع می‌شود
		return
	}

	targetAddr := parts[1]
	// اتصال به اینترنت واقعی
	target, err := net.DialTimeout("tcp", targetAddr, 10*time.Second)
	if err != nil {
		return
	}
	defer target.Close()

	stream.SetReadDeadline(time.Time{}) // حذف محدودیت زمانی بعد از تایید

	done := make(chan struct{})
	go func() { io.Copy(target, stream); done <- struct{}{} }()
	go func() { io.Copy(stream, target); done <- struct{}{} }()
	<-done
}

func generateSelfSignedCert() (tls.Certificate, error) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour * 24 * 365),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	certBytes, _ := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	var certBuf, keyBuf strings.Builder
	pem.Encode(&certBuf, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	pem.Encode(&keyBuf, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	return tls.X509KeyPair([]byte(certBuf.String()), []byte(keyBuf.String()))
}
