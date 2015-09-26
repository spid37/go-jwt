# go-jwt

generate and verify json web tokens using https://github.com/dgrijalva/jwt-go

RSA keys tokens only.

#### Examples 

##### generate jwt
```go
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
```
##### verify jwt
```go
jwt := gojwt.New(gojwt.Options{
		PrivateKeyPath: "keys/private_key.pem",
		PublicKeyPath:  "keys/public_key.pem",
	})

	tokenData, err := jwt.Verify(token)
	if err != nil {
		t.Errorf("Failed to verify token")
	}

	```
