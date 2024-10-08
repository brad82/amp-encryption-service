package main

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/gin-gonic/gin"
)

func encodeFragment(c *gin.Context) {
	f, err := io.ReadAll(c.Request.Body)
	if err != nil {
		c.IndentedJSON(http.StatusBadRequest, gin.H{
			"error": "Could not read fragment",
		})
		return
	}

	er, err := GenerateEncryptedFragment(f, []string{
		"Memoori.Subscription",
	}, pubKeys)

	if err != nil {
		c.IndentedJSON(http.StatusBadRequest, gin.H{
			"error": err,
		})
		return
	}

	c.IndentedJSON(http.StatusOK, er)
}

func decodeDocumentKey(c *gin.Context) {
	crypt := c.DefaultQuery("crypt", "")
	if len(crypt) == 0 {
		c.IndentedJSON(http.StatusBadRequest, errors.New("invalid crypt token"))
		return
	}

	bc, err := base64.URLEncoding.DecodeString(crypt)
	if err != nil {
		c.IndentedJSON(http.StatusInternalServerError, gin.H{
			"error": fmt.Sprint("Unknown error: ", err),
		})
		return
	}

	dc, err := DecryptCrypt(bc, privKey)
	if err != nil {
		c.IndentedJSON(http.StatusInternalServerError, gin.H{
			"error": fmt.Sprint("Unknown error: ", err),
		})
		return
	}

	c.Data(http.StatusOK, "application/json", []byte(*dc))
}
