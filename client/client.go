package main

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httputil"

	"github.com/blck-snwmn/client-auth/root"
)

func main() {
	req, _ := http.NewRequest("GET", "https://localhost:18080", nil)
	cert, err := tls.LoadX509KeyPair("./cert.pem", "./key.pem")
	if err != nil {
		fmt.Println("LoadX509KeyPair err!", err)
		return
	}
	client := http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:      root.GetCertPool(),
				Certificates: []tls.Certificate{cert},
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
