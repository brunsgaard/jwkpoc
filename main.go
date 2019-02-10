package main

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/lestrrat-go/jwx/jwk"
)

const jwksURL = `https://connect.visma.com/.well-known/openid-configuration/jwks`

func getKey(token *jwt.Token) (interface{}, error) {

	set, err := jwk.Fetch(jwksURL)
	if err != nil {
		return nil, err
	}

	keyID, ok := token.Header["kid"].(string)
	if !ok {
		return nil, errors.New("Expecting JWT header to have string kid")
	}
	println(keyID)
	key := set.LookupKeyID(keyID)
	println(key)
	if len(key) == 1 {
		return key[0].Materialize()
	}
	return nil, errors.New("Unable to find key")
}

func main() {
	tokenbytes, _ := ioutil.ReadAll(os.Stdin)
	token, err := jwt.Parse(string(tokenbytes), getKey)
	if err != nil {
		panic(err)
	}
	claims := token.Claims.(jwt.MapClaims)
	for key, value := range claims {
		fmt.Printf("%s\t%v\n", key, value)
	}
}
