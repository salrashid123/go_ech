package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
)

var (
	hconfig = "AEv+DQBHewAgACCMyX4rqyZYot8XeCJ2bkDtFQT6obsNU0TCHEmzn1MEdAAMAAEAAQABAAIAAQADIBBwcm94eS5kb21haW4uY29tAAA="
)

func main() {

	domain := "backend.domain.com"

	caCert, err := os.ReadFile("certs/root-ca.crt")
	if err != nil {
		fmt.Println(err)
		return
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	echConfigListBytes, err := base64.StdEncoding.DecodeString(hconfig)
	if err != nil {
		fmt.Printf("Error decoding configlist %v", err)
		return
	}

	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
		ServerName: domain,
		RootCAs:    caCertPool,
		EncryptedClientHelloRejectionVerify: func(cs tls.ConnectionState) error {
			if !cs.ECHAccepted {
				return errors.New("ECH not accepted")
			}
			return nil
		},
		EncryptedClientHelloConfigList: echConfigListBytes,
	}

	sslKeyLogfile := os.Getenv("SSLKEYLOGFILE")
	if sslKeyLogfile != "" {
		var w *os.File
		w, err := os.OpenFile(sslKeyLogfile, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
		if err != nil {
			fmt.Printf("Could not create keylogger: %v\n", err)
			return
		}
		tlsConfig.KeyLogWriter = w
	}

	tr := &http.Transport{
		TLSClientConfig: tlsConfig,
	}
	client := &http.Client{Transport: tr}

	resp, err := client.Get(fmt.Sprintf("https://%s:8081", "localhost"))
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("ECHAccepted %t\n", resp.TLS.ECHAccepted)
	htmlData, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer resp.Body.Close()
	fmt.Printf("%v\n", resp.Status)
	fmt.Println(string(htmlData))

}
