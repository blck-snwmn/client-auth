package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"time"

	"golang.org/x/xerrors"
)

func readPrivateKey(pemFile string) (*rsa.PrivateKey, error) {
	bytes, err := ioutil.ReadFile(pemFile)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(bytes)
	if block == nil {
		return nil, xerrors.New("load failed")
	}

	var key *rsa.PrivateKey
	switch block.Type {
	case "PRIVATE KEY":
		keyInterface, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		var ok bool
		key, ok = keyInterface.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("not RSA private key")
		}
	default:
		return nil, xerrors.New("no support type")
	}

	key.Precompute()
	if err := key.Validate(); err != nil {
		return nil, err
	}
	return key, nil
}
func readCertificate(path string) (*x509.Certificate, error) {
	bytes, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(bytes)
	if block == nil {
		return nil, xerrors.New("invalid certificate key data")
	}
	return x509.ParseCertificate(block.Bytes)
}

func main() {
	tlsCert, err := tls.LoadX509KeyPair("./root/cert.pem", "./root/key.pem")
	if err != nil {
		fmt.Println("error!", err)
		return
	}
	x509Cert, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		fmt.Println("error!", err)
		return
	}

	now := time.Now()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Println("error!", err)
		return
	}
	pub := &priv.PublicKey
	cb, err := x509.CreateCertificate(
		rand.Reader,
		&x509.Certificate{
			SerialNumber: big.NewInt(1235),
			DNSNames:     []string{"localhost"},
			NotBefore:    now,
			NotAfter:     now.AddDate(1, 0, 0),
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
			KeyUsage:     x509.KeyUsageDigitalSignature,
		}, x509Cert,
		pub, tlsCert.PrivateKey,
	)
	f, err := os.Create("./create_cert/key.pem")
	if err != nil {
		fmt.Println("error!", err)
		return
	}
	err = pem.Encode(f, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	if err != nil {
		fmt.Println("error!", err)
		return
	}
	f, err = os.Create("./create_cert/cert.pem")
	if err != nil {
		fmt.Println("error!", err)
		return
	}
	err = pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: cb})
	if err != nil {
		fmt.Println("error!", err)
		return
	}
	b, _ := ioutil.ReadFile("./create_cert/key.pem")
	block, _ := pem.Decode(b)
	if block == nil {
		fmt.Println("err block is nil")
		return
	}
	fmt.Println(block.Type)
}
