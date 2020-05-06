package main

import (
	"crypto/tls"
	"log"
	"net/http"

	"github.com/blck-snwmn/client-auth/root"
)

func handler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(200)
}
func main() {
	var server http.Server
	server.Addr = ":18080"
	server.TLSConfig = &tls.Config{
		ClientCAs:  root.GetCertPool(),
		ClientAuth: tls.RequireAndVerifyClientCert,
	}
	http.HandleFunc("/", handler)
	log.Println(server.ListenAndServeTLS("./cert.pem", "./key.pem"))
}
