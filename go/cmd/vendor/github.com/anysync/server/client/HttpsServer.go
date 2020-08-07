// Copyright (c) 2020, Yanbin (Henry) Zheng <ybzheng@gmail.com>
// All rights reserved.
//
// Use of this source code is governed by a AGPLv3 license that can be
// found in the LICENSE file.
package client

import (
	"crypto/x509"
	"encoding/pem"
	"crypto/rsa"
	"log"
	"net"
	"crypto/tls"
	"net/http"
	"math/big"
	"crypto/x509/pkix"
	"time"
	"crypto/rand"
	"errors"
	utils "github.com/anysync/server/utils"
)

// helper function to create a cert template with a serial number and other required fields
func CertTemplate() (*x509.Certificate, error) {// https://ericchiang.github.io/post/go-tls/
	// generate a random serial number (a real cert authority would have some logic behind this)
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, errors.New("failed to generate serial number: " + err.Error())
	}

	tmpl := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{Organization: []string{"AnySync"}},
		SignatureAlgorithm:    x509.SHA256WithRSA,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(10*8760*time.Hour), // valid for 10 years
		BasicConstraintsValid: true,
	}
	return &tmpl, nil
}

func CreateCert(template, parent *x509.Certificate, pub interface{}, parentPriv interface{}) (
	cert *x509.Certificate, certPEM []byte, err error) {

	certDER, err := x509.CreateCertificate(rand.Reader, template, parent, pub, parentPriv)
	if err != nil {
		return
	}
	// parse the resulting certificate so we can use it again
	cert, err = x509.ParseCertificate(certDER)
	if err != nil {
		return
	}
	// PEM encode the certificate (this is a standard TLS encoding)
	b := pem.Block{Type: "CERTIFICATE", Bytes: certDER}
	certPEM = pem.EncodeToMemory(&b)
	return
}

func InitServer() {
	//utils.Log = utils.NewLogger("")
	if(utils.CurrentFileExists()){
		go initializeLocalServer()
	}
	utils.Listener(false, "", nil);
	StartHttpsServer();
	//DON'T put code here, because it won't reach here.
}

func StartHttpsServer(){
	// create a key-pair for the server
	// generate a new key-pair
	rootKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("generating random key: %v", err)
	}

	rootCertTmpl, err := CertTemplate()
	if err != nil {
		log.Fatalf("creating cert template: %v", err)
	}
	// describe what the certificate will be used for
	rootCertTmpl.IsCA = true
	rootCertTmpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature
	rootCertTmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	rootCertTmpl.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}

	_, rootCertPEM, err := CreateCert(rootCertTmpl, rootCertTmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		log.Fatalf("error creating cert: %v", err)
	}
	//fmt.Printf("%s\n", rootCertPEM)
	//fmt.Printf("%#x\n", rootCert.Signature) // more ugly binary

	// PEM encode the private key
	rootKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rootKey),
	})

	// Create a TLS cert using the private key and certificate
	rootTLSCert, err := tls.X509KeyPair(rootCertPEM, rootKeyPEM)
	if err != nil {
		log.Fatalf("invalid key pair: %v", err)
	}

	s := &http.Server{Addr: utils.LOCAL_HTML_PORT, Handler: nil}

	// Configure the server to present the certficate we created
	s.TLSConfig = &tls.Config{
		Certificates: []tls.Certificate{rootTLSCert},
	}
	s.ListenAndServe()
	//s.ListenAndServeTLS("", "");
}
