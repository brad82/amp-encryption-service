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
	km["memoori.com"] = "https://memoori.com/.well-known/swg/tink/pubkey.json"
	km["google.com"] = googleDevPublicKeyURL

	for domain, url := range km {
		pubKey, err := RetrieveTinkPublicKey(url)
		if err != nil {
			log.Fatal(err)
		}
		pubKeys[strings.ToLower(domain)] = pubKey
	}
}

func initPrivateKeys() {
	sk := os.Getenv("PRIVATE_KEY")
	if len(sk) == 0 {
		log.Fatal("Cannot start application without a private key")
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
	r.POST("/", encodeFragment)
	r.GET("authorize", decodyDocumentKey)

	r.Run(":8080")
}
