package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(200)
}
func main() {
	b, _ := ioutil.ReadFile("../root/ca.crt")
	block, _ := pem.Decode(b)
	if block == nil {
		fmt.Println("block err!")
		return
	}
	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		fmt.Println("x509Cert err!", err)
		return
	}
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	var server http.Server
	server.Addr = ":18080"

	server.TLSConfig = &tls.Config{
		ClientCAs:  pool,
		ClientAuth: tls.RequireAndVerifyClientCert,
	}
	http.HandleFunc("/", handler)
	log.Println(server.ListenAndServeTLS("./cert.pem", "./key.pem"))
}
