package main

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

const PSK_TOKEN_PREFIX = "Bearer "

func AuthenticateWithPSK(psk string) gin.HandlerFunc {
	return func(c *gin.Context) {
		bt := c.GetHeader("Authorization")

		if !strings.HasPrefix(bt, PSK_TOKEN_PREFIX) {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
				"error": "Not Authorized",
			})
			return
		}

		k := strings.TrimPrefix(bt, PSK_TOKEN_PREFIX)
		if k == psk {
			c.Next()
			return
		}

		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
			"error": "Not Authorized",
		})
	}
}
