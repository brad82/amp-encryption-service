package main

import (
	"bytes"
	"log"
	"os"
	"strings"

	"github.com/gin-gonic/gin"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"

	_ "github.com/joho/godotenv/autoload"
)

const googleDevPublicKeyURL string = "https://news.google.com/swg/encryption/keys/dev/tink/public_key"

var pubKeys map[string]tinkpb.Keyset = make(map[string]tinkpb.Keyset)
var privKey tinkpb.Keyset

func initPublicKeys() {
	km := make(map[string]string)
	km["google.com"] = googleDevPublicKeyURL
	km["local"] = "https://memoori.com/.well-known/swg/tink/pubkey.json"

	for domain, url := range km {
		pubKey, err := RetrieveTinkPublicKey(url)
		if err != nil {
			log.Fatal(err)
		}
		pubKeys[strings.ToLower(domain)] = pubKey
	}
}

func initPrivateKeys() {
	sk := os.Getenv("AMP_API_PRIVATE_KEY")
	if len(sk) == 0 {
		log.Fatal("Cannot start application without a private key (AMP_API_PRIVATE_KEY)")
	}
	r := bytes.NewBufferString(sk)
	pk, err := ReadTinkPrivKey(r)
	if err != nil {
		log.Fatal(err)
	}

	privKey = pk
}

func main() {
	initPublicKeys()
	initPrivateKeys()

	r := gin.Default()

	psk := os.Getenv("AMP_API_PSK")
	if len(psk) == 0 {
		log.Fatal("Cannot start application without a pre-shared API key (AMP_API_PSK)")
		return
	}

	r.Use(AuthenticateWithPSK(psk))

	r.POST("/", encodeFragment)
	r.GET("/", decodeDocumentKey)

	r.Run(":8080")
}
