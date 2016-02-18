package token_test

import (
	"bufio"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"testing"

	ts "github.com/jaybgo/token"
)

const (
	privateKeyPath = "./tests/privatekey"
	publicKeyPath  = "./tests/publickey.pub"
)

var (
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
)

func TestMain(m *testing.M) {
	var err error

	privateKey, err = getPrivateKey(privateKeyPath)
	if err != nil {
		panic(err)
		return
	}

	publicKey, err = getPublicKey(publicKeyPath)
	if err != nil {
		panic(err)
		return
	}

	ret := m.Run()
	os.Exit(ret)
}

func TestToken(t *testing.T) {
	token, err := ts.CreateToken(privateKey, "123456789012345678901234567890123456")
	if err != nil {
		t.Error(err)
		return
	}

	if err := token.IsValid(publicKey); err != nil {
		t.Error(err)
		return
	}

	tokenString := token.GetTokenString()

	parseToken, err := ts.ParseToken(tokenString)
	if err != nil {
		t.Error(err)
		return
	}

	if err := parseToken.IsValid(publicKey); err != nil {
		t.Error(err)
		return
	}
}

func getPrivateKey(path string) (*rsa.PrivateKey, error) {
	privateKeyFile, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	defer privateKeyFile.Close()

	pemFileInfo, err := privateKeyFile.Stat()
	if err != nil {
		return nil, err
	}

	size := pemFileInfo.Size()
	pemBytes := make([]byte, size)

	buffer := bufio.NewReader(privateKeyFile)

	if _, err := buffer.Read(pemBytes); err != nil {
		return nil, err
	}

	data, _ := pem.Decode([]byte(pemBytes))

	privateKeyImported, err := x509.ParsePKCS1PrivateKey(data.Bytes)
	if err != nil {
		return nil, err
	}

	return privateKeyImported, nil
}

func getPublicKey(path string) (*rsa.PublicKey, error) {
	publicKeyFile, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	defer publicKeyFile.Close()

	pemFileInfo, err := publicKeyFile.Stat()
	if err != nil {
		return nil, err
	}

	size := pemFileInfo.Size()
	pemBytes := make([]byte, size)

	buffer := bufio.NewReader(publicKeyFile)

	if _, err := buffer.Read(pemBytes); err != nil {
		return nil, err
	}

	data, _ := pem.Decode([]byte(pemBytes))

	publicKeyImported, err := x509.ParsePKIXPublicKey(data.Bytes)
	if err != nil {
		return nil, err
	}

	rsaPub, ok := publicKeyImported.(*rsa.PublicKey)
	if !ok {
		return nil, nil
	}

	return rsaPub, nil
}
