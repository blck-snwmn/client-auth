package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httputil"

	"golang.org/x/xerrors"
)

func readCert(path string) (*x509.Certificate, error) {
	b, _ := ioutil.ReadFile(path)
	block, _ := pem.Decode(b)
	if block == nil {
		fmt.Println("block err!")
		return nil, xerrors.New("no pem")
	}
	return x509.ParseCertificate(block.Bytes)
}

func main() {
	req, _ := http.NewRequest("GET", "https://localhost:18080", nil)
	cert, err := tls.LoadX509KeyPair("./client/cert.pem", "./client/key.pem")
	if err != nil {
		fmt.Println("LoadX509KeyPair err!", err)
		return
	}
	caCert, err := readCert("./root/ca.crt")
	if err != nil {
		fmt.Println("caCert err!", err)
		return
	}
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	client := http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates: []tls.Certificate{cert},
				RootCAs:      pool,
			},
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("request error is %v\n", err)
		return
	}
	defer resp.Body.Close()
	dump, err := httputil.DumpResponse(resp, false)
	if err != nil {
		fmt.Printf("dump err is %v\n", err)
		return
	}
	fmt.Println(string(dump))
}
