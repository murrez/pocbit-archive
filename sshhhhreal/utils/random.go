package utils

import (
	"math/rand"
	"time"
)

const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

var r = rand.New(rand.NewSource(time.Now().UnixNano()))

func RandomString(size int) string {
	b := make([]byte, size)
	for i := range b {
		b[i] = charset[r.Intn(len(charset))]
	}
	return string(b)
}

func RandomInt(n int) int {
	return r.Intn(n)
}
