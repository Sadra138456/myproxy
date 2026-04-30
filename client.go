package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"log"
	"net"
	"os"
	"time"

	"github.com/quic-go/quic-go"
)

type Config struct {
	ServerIP   string `json:"server_ip"`
	LocalProxy string `json:"local_proxy"`
}

func main() {
	content, _ := os.ReadFile("config.json")
	var config Config
	json.Unmarshal(content, &config)

	tlsConf := &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h3"}}
	quicConf := &quic.Config{EnableDatagrams: true, MaxIdleTimeout: 60 * time.Second}

	serverConn, err := quic.DialAddr(context.Background(), config.ServerIP+":443", tlsConf, quicConf)
	if err != nil {
		log.Fatal(err)
	}

	listener, _ := net.Listen("tcp", config.LocalProxy)
	log.Printf("✈️ F-35 Client: %s", config.LocalProxy)

	for {
		clientConn, err := listener.Accept()
		if err != nil {
			continue
		}
		go func(cc net.Conn) {
			defer cc.Close()
			// در اینجا ما یک اتصال ساده ایجاد می‌کنیم. 
			// کلاینت شما (مرورگر) باید روی Socks5 تنظیم شده باشد.
			// برای سادگی، این ورژن فقط ترافیک را Forward می‌کند.
			stream, _ := serverConn.OpenStreamSync(context.Background())
			defer stream.Close()
			
			// این بخش به صورت ساده ترافیک را جابه‌جا می‌کند
			go io.Copy(stream, cc)
			io.Copy(cc, stream)
		}(clientConn)
	}
}
