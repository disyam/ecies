package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"log"
	"math/big"

	"github.com/gofiber/fiber/v2"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

func encrypt(secret, plaintext []byte) (nonce, ciphertext []byte, err error) {
	var block cipher.Block
	block, err = aes.NewCipher(secret)
	if err != nil {
		return
	}
	var aesgcm cipher.AEAD
	aesgcm, err = cipher.NewGCM(block)
	if err != nil {
		return
	}
	nonce = make([]byte, 12)
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return
	}
	ciphertext = aesgcm.Seal(nil, nonce, plaintext, nil)
	return
}

func decrypt(secret, nonce, ciphertext []byte) (plaintext []byte, err error) {
	var block cipher.Block
	block, err = aes.NewCipher(secret)
	if err != nil {
		return
	}
	var aesgcm cipher.AEAD
	aesgcm, err = cipher.NewGCM(block)
	if err != nil {
		return
	}
	plaintext, err = aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return
	}
	return
}

func main() {
	var err error

	var servPrivBytes []byte
	var servPrivX, servPrivY *big.Int
	servPrivBytes, servPrivX, servPrivY, err = elliptic.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalln(err)
	}
	var servPriv ecdsa.PrivateKey
	servPriv.D = new(big.Int).SetBytes(servPrivBytes)
	servPriv.PublicKey = ecdsa.PublicKey{X: servPrivX, Y: servPrivY, Curve: elliptic.P256()}
	var servPubJWK jwk.Key
	servPubJWK, err = jwk.FromRaw(servPriv.PublicKey)
	if err != nil {
		log.Fatalln(err)
	}
	err = servPubJWK.Set(jwk.AlgorithmKey, "ECDH")
	if err != nil {
		log.Fatalln(err)
	}

	app := fiber.New()

	app.Post("/add", func(c *fiber.Ctx) (err error) {
		var body map[string]int
		err = json.Unmarshal(c.Body(), &body)
		if err != nil {
			return
		}
		err = c.JSON(map[string]int{"c": body["a"] + body["b"]})
		return
	})

	app.Get("/pub", func(c *fiber.Ctx) (err error) {
		err = c.JSON(servPubJWK)
		return
	})

	app.Use(func(c *fiber.Ctx) (err error) {
		var body map[string]string
		err = json.Unmarshal(c.Body(), &body)
		if err != nil {
			return
		}
		var cliPubBytes []byte
		cliPubBytes, err = base64.StdEncoding.DecodeString(body["p"])
		if err != nil {
			return
		}
		var cliPub ecdsa.PublicKey
		err = jwk.ParseRawKey(cliPubBytes, &cliPub)
		if err != nil {
			return
		}
		secret, _ := elliptic.P256().ScalarMult(cliPub.X, cliPub.Y, servPrivBytes)
		var nonce []byte
		nonce, err = base64.StdEncoding.DecodeString(body["i"])
		if err != nil {
			return
		}
		var ciphertext []byte
		ciphertext, err = base64.StdEncoding.DecodeString(body["c"])
		if err != nil {
			return
		}
		var plaintext []byte
		plaintext, err = decrypt(secret.Bytes(), nonce, ciphertext)
		if err != nil {
			return
		}
		c.Locals("body", plaintext)
		c.Locals("secret", secret.Bytes())
		err = c.Next()
		return
	})

	app.Post("/adds", func(c *fiber.Ctx) (err error) {
		var body map[string]int
		err = json.Unmarshal(c.Locals("body").([]byte), &body)
		if err != nil {
			return
		}
		secret := c.Locals("secret").([]byte)
		var plaintext []byte
		plaintext, err = json.Marshal(map[string]int{"c": body["a"] + body["b"]})
		if err != nil {
			return
		}
		var nonce, ciphertext []byte
		nonce, ciphertext, err = encrypt(secret, plaintext)
		if err != nil {
			return
		}
		err = c.JSON(map[string]string{
			"i": base64.StdEncoding.EncodeToString(nonce),
			"c": base64.StdEncoding.EncodeToString(ciphertext),
		})
		return
	})

	err = app.Listen(":8080")
	if err != nil {
		log.Fatalln(err)
	}
}
