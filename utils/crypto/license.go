package crypto

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
)

const (
	public_key_pem = `-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCuuMF+J+k949fhPKx7fSpVQlly
l8iWFUQoZIoit7buzeJP3wd1PMxTMNFm8lLDE8fltT4/ChAMvb5wmq9s/DmzzFum
m54loo8e+XXdxtZfUQJmtlYUTsEI+M4UNBoFw9E79E5pySLfdXTPEYyIleNhxwpR
q9L0D+04TJ+DdiJlIwIDAQAB
-----END PUBLIC KEY-----`
)

func Verify(customerCode string, license string) error {
	block, _ := pem.Decode([]byte(public_key_pem))
	rawKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return err
	}
	rsaPublicKey, ok := rawKey.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("Cannot find public key")
	}
	ds, _ := base64.StdEncoding.DecodeString(license)
	return unsign(rsaPublicKey, []byte(customerCode), ds)
}

func unsign(pubKey *rsa.PublicKey, message []byte, sig []byte) error {
	h := sha256.New()
	h.Write(message)
	d := h.Sum(nil)
	return rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, d, sig)
}
