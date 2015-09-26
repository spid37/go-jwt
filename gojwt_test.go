package gojwt_test

import (
	"testing"

	"github.com/spid37/jwt-go-wrapper"
)

var token string

func TestGenerate(t *testing.T) {
	var err error
	jwt := gojwt.New(gojwt.Options{
		PrivateKeyPath: "keys/private_key.pem",
		PublicKeyPath:  "keys/public_key.pem",
	})

	tokenData := map[string]string{
		"test": "testing",
	}

	token, err = jwt.GenerateToken(tokenData)
	if err != nil {
		t.Errorf("Failed to generate token")
	}
}

func TestVerify(t *testing.T) {
	jwt := gojwt.New(gojwt.Options{
		PrivateKeyPath: "keys/private_key.pem",
		PublicKeyPath:  "keys/public_key.pem",
	})

	tokenData, err := jwt.Verify(token)
	if err != nil {
		t.Errorf("Failed to verify token")
	}

	if val, ok := tokenData["test"]; ok {
		if val != "testing" {
			t.Errorf("Token data expected 'testing' got '%s'", val)
		}
	} else {
		t.Errorf("Failed to read token data")
	}

}
