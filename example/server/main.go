package main

import (
	"crypto/ecdh"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/gorilla/mux"
	echutil "github.com/salrashid123/go_ech/util"
	"golang.org/x/net/http2"
)

var ()

const ()

func eventsMiddleware(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Printf("SNI ServerName: %s\n", r.TLS.ServerName)
		h.ServeHTTP(w, r)
	})
}

func gethandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, "ok")
}

func main() {

	router := mux.NewRouter()
	router.Methods(http.MethodGet).Path("/").HandlerFunc(gethandler)

	var err error

	server1_cert, err := tls.LoadX509KeyPair("certs/proxy.crt", "certs/proxy.key")
	if err != nil {
		log.Fatal("failed to load frontend certificate:", err)
	}

	backendCert, err := tls.LoadX509KeyPair("certs/backend.crt", "certs/backend.key")
	if err != nil {
		log.Fatal("failed to load backend certificate:", err)
	}

	pemData, err := os.ReadFile("certs/ecdh_private_key.pem")
	if err != nil {
		fmt.Println("Error reading PEM file:", err)
		return
	}

	block, _ := pem.Decode(pemData)
	if block == nil {
		fmt.Println("Error decoding PEM block")
		return
	}

	ecdhSKBytes, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		fmt.Println("failed to marshal private key into PKIX format")
		return
	}

	privateKey := ecdhSKBytes.(*ecdh.PrivateKey)

	echConfigList, err := echutil.GetECHConfigList(privateKey, []string{"proxy.domain.com"})
	if err != nil {
		fmt.Println("failed to get echconfiglist")
		return
	}

	echConfig, err := echutil.GetECHConfig(privateKey, "proxy.domain.com")
	if err != nil {
		fmt.Println("failed to get echConfig")
		return
	}

	fmt.Printf("ECHConfig: %s\n", base64.StdEncoding.EncodeToString(echConfig))
	fmt.Printf("echConfigList Std: %s\n", base64.StdEncoding.EncodeToString(echConfigList))

	// &&****************************

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{server1_cert, backendCert},

		MinVersion:       tls.VersionTLS13,
		MaxVersion:       tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{},

		EncryptedClientHelloKeys: []tls.EncryptedClientHelloKey{{
			Config:      echConfig,
			PrivateKey:  privateKey.Bytes(),
			SendAsRetry: true,
		}},
	}

	server := &http.Server{
		Addr:      ":8081",
		Handler:   eventsMiddleware(router),
		TLSConfig: tlsConfig,
	}
	http2.ConfigureServer(server, &http2.Server{})
	fmt.Println("Starting Server..")
	err = server.ListenAndServeTLS("", "")
	fmt.Printf("Unable to start Server %v", err)

}
