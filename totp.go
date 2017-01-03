package totp

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"io"
	"log"
	"strconv"
)

//Input for the TOTP generator.
//AvailableForSeconds must be > 0 and Digits > 6
type GenerateInput struct {
	Digits              uint16
	Time                int64
	AvailableForSeconds byte
}

//shamelessly copied from rfc
const key string = "3132333435363738393031323334353637383930313233343536373839303132"

var digitsPower []int = []int{1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000}

func hMacOf(msg string, key []byte) []byte {
	mac := hmac.New(sha256.New, key)
	io.WriteString(mac, msg)
	r := mac.Sum(nil)
	return r
}

//Generates one-time password based on input
func GenerateTOTP(in GenerateInput) string {
	if in.AvailableForSeconds == 0 {
		log.Fatal("Must be available for at least 1 second")
	}

	if in.Digits < 6 {
		log.Fatal("Digits must be at least 6")
	}

	t := in.Time / int64(in.AvailableForSeconds)
	ht := fmt.Sprintf("%x", t)
	for len(ht) < 16 {
		ht = "0" + ht
	}

	hash := hMacOf(ht, []byte(key))
	offset := hash[len(hash)-1] & 0xf

	binary := (int32(hash[offset]&0x7f) << 24) |
		(int32(hash[offset+1]&0xff) << 16) |
		(int32(hash[offset+2]&0xff) << 8) |
		int32(hash[offset+3]&0xff)

	md := digitsPower[in.Digits]
	otp := int(binary) % md

	result := strconv.Itoa(otp)
	for len(result) < int(in.Digits) {
		result = "0" + result
	}

	return result
}
