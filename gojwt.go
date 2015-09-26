package gojwt

import (
	"crypto/rsa"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"time"

	"github.com/dgrijalva/jwt-go"
)

// Options is a struct for specifying configuration options for the middleware.
type Options struct {
	PrivateKeyPath string
	PublicKeyPath  string
	// Time in minutes untill the token will expire
	ExpireMins int
	// Debug flag turns on debugging output
	// Default: false
	Debug bool
	// When set, all requests with the OPTIONS method will use authentication
	// Default: false
	EnableAuthOnOptions bool
}

// Keys - keys are stored here
type Keys struct {
	VerifyKey *rsa.PublicKey
	SignKey   *rsa.PrivateKey
}

func (k *Keys) loadPrivateKey(privateKeyPath string) error {
	var err error

	if privateKeyPath == "" {
		err = fmt.Errorf("Private keys are required")
		return err
	}

	// load the private key
	if _, err := os.Stat(privateKeyPath); err == nil {
		signBytes, err := ioutil.ReadFile(privateKeyPath)
		if err != nil {
			return err
		}
		k.SignKey, err = jwt.ParseRSAPrivateKeyFromPEM(signBytes)
		if err != nil {
			return err
		}
	} else {
		return err
	}

	return err
}

func (k *Keys) loadPublicKey(publicKeyPath string) error {
	var err error

	if publicKeyPath == "" {
		err = fmt.Errorf("Public key is required")
		return err
	}

	// load the public key
	if _, err := os.Stat(publicKeyPath); err == nil {
		verifyBytes, err := ioutil.ReadFile(publicKeyPath)
		if err != nil {
			return err
		}
		k.VerifyKey, err = jwt.ParseRSAPublicKeyFromPEM(verifyBytes)
		if err != nil {
			return err
		}
	}

	return err
}

// GoJWT - GoJWT for handeling jwt
type GoJWT struct {
	Options Options
	*Keys
}

// New  - constructs a new Secure instance with supplied options.
func New(options ...Options) *GoJWT {

	var opts Options
	var keys Keys
	var err error

	if len(options) == 0 {
		opts = Options{}
	} else {
		opts = options[0]
	}

	err = keys.loadPrivateKey(opts.PrivateKeyPath)
	err = keys.loadPublicKey(opts.PublicKeyPath)
	if err != nil {
		log.Fatal(err)
	}

	if opts.ExpireMins == 0 {
		opts.ExpireMins = 5
	}

	return &GoJWT{
		Options: opts,
		Keys:    &keys,
	}
}

func (m *GoJWT) logf(format string, args ...interface{}) {
	if m.Options.Debug {
		log.Printf(format, args...)
	}
}

// GenerateToken - generate a new token
func (m *GoJWT) GenerateToken(claims map[string]string) (string, error) {
	// Create the token
	token := jwt.New(jwt.SigningMethodRS256)
	// Set some claims
	for c, v := range claims {
		token.Claims[c] = v
	}

	// expire time
	token.Claims["exp"] = time.Now().Add(time.Minute * time.Duration(m.Options.ExpireMins)).Unix()
	// original creation time
	token.Claims["iat_orginal"] = time.Now().Unix()
	// this token creation time.
	token.Claims["iat"] = time.Now().Unix()
	token.Claims["count"] = 1
	// Sign and get the complete encoded token as a string
	tokenString, err := token.SignedString(m.SignKey)
	return tokenString, err
}

// DecodeToken - get token from header and verify it
func (m *GoJWT) DecodeToken(token string) (*jwt.Token, error) {

	// If the token is empty...
	if token == "" {
		// If we get here, the required token is missing
		errorMsg := "Required authorization token not found"
		return nil, fmt.Errorf(errorMsg)
	}

	// Now parse the token
	// parsedToken, err := jwt.Parse(token, m.Options.ValidationKeyGetter)
	// validate the token
	parsedToken, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		// verify signing method
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		// since we only use the one private key to sign the tokens,
		// we also only use its public counter part to verify
		return m.VerifyKey, nil
	})

	// Check if there was an error in parsing...
	if err != nil {
		m.logf("Error parsing token: %v", err)
		return parsedToken, fmt.Errorf("Error parsing token: %v", err)
	}
	return parsedToken, err
}

// Verify check token
func (m *GoJWT) Verify(token string) (map[string]interface{}, error) {
	var err error

	parsedToken, err := m.DecodeToken(token)

	if err != nil {
		m.logf("Error parsing token: %v", err)
		return nil, err
	}

	// Check if the parsed token is valid...
	if !parsedToken.Valid {
		m.logf("Token is invalid")
		return nil, fmt.Errorf("Token is invalid")
	}

	return parsedToken.Claims, err
}
