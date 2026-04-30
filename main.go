package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"log"
	"math/big"
	"net"
	"time"

	"github.com/quic-go/quic-go"
)

func main() {
	tlsConf := generateTLSConfig()
	quicConf := &quic.Config{
		Allow0RTT:       true,
		EnableDatagrams: true,
		MaxIdleTimeout:  60 * time.Second,
	}

	listener, err := quic.ListenAddr(":443", tlsConf, quicConf)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("🚀 F-35 Server Active on Port 443")

	for {
		conn, err := listener.Accept(context.Background())
		if err != nil {
			continue
		}
		go handleMaster(conn)
	}
}

func handleMaster(conn quic.Connection) {
	for {
		stream, err := conn.AcceptStream(context.Background())
		if err != nil {
			break
		}
		go func(s quic.Stream) {
			defer s.Close()
			// خواندن آدرس مقصد از کلاینت (ساده شده)
			// برای سادگی، کلاینت در اولین پکت آدرس را می‌فرستد
			buf := make([]byte, 1024)
			n, err := s.Read(buf)
			if err != nil {
				return
			}
			targetAddr := string(buf[:n])
			
			target, err := net.DialTimeout("tcp", targetAddr, 10*time.Second)
			if err != nil {
				return
			}
			defer target.Close()

			go io.Copy(target, s)
			io.Copy(s, target)
		}(stream)
	}
}

func generateTLSConfig() *tls.Config {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	template := x509.Certificate{SerialNumber: big.NewInt(1)}
	certDER, _ := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	tlsCert, _ := tls.X509KeyPair(certPEM, keyPEM)
	return &tls.Config{Certificates: []tls.Certificate{tlsCert}, NextProtos: []string{"h3"}}
}
