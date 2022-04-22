package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"

	"github.com/gofiber/fiber/v2"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"golang.org/x/crypto/curve25519"
)

func encrypt(secret, plaintext []byte) (nonce, ciphertext, signature []byte, err error) {
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
	mac := hmac.New(sha256.New, secret)
	mac.Write(ciphertext)
	signature = mac.Sum(nil)
	return
}

func decrypt(secret, nonce, ciphertext, signature []byte) (plaintext []byte, err error) {
	mac := hmac.New(sha256.New, secret)
	mac.Write(ciphertext)
	if !hmac.Equal(mac.Sum(nil), signature) {
		err = fmt.Errorf("signature not match")
		return
	}
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

func generateP256() (key jwk.Key, err error) {
	var priv *ecdsa.PrivateKey
	priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return
	}
	key, err = jwk.FromRaw(priv)
	if err != nil {
		return
	}
	err = key.Set(jwk.KeyIDKey, "P-256")
	if err != nil {
		return
	}
	err = key.Set(jwk.AlgorithmKey, "ECDH")
	if err != nil {
		log.Fatalln(err)
	}
	return
}

func generateX25519() (key jwk.Key, err error) {
	var priv, pub [32]byte
	_, err = io.ReadFull(rand.Reader, priv[:])
	if err != nil {
		return
	}
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64
	curve25519.ScalarBaseMult(&pub, &priv)
	return
}

func main() {
	var err error

	var privJWK jwk.Key
	privJWK, err = generateP256()
	if err != nil {
		log.Fatalln(err)
	}
	jwks := jwk.NewSet()
	valid := jwks.Add(privJWK)
	if !valid {
		log.Fatalln(errors.New("cant add key to key set"))
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

	app.Get("/jwks", func(c *fiber.Ctx) (err error) {
		pubJWKS, err := jwk.PublicSetOf(jwks)
		if err != nil {
			return
		}
		err = c.JSON(pubJWKS)
		return
	})

	app.Use(func(c *fiber.Ctx) (err error) {
		var body map[string]interface{}
		err = json.Unmarshal(c.Body(), &body)
		if err != nil {
			return
		}
		var cliPubBytes []byte
		cliPubBytes, err = json.Marshal(body["p"].(map[string]interface{}))
		if err != nil {
			return
		}
		var cliPub ecdsa.PublicKey
		err = jwk.ParseRawKey(cliPubBytes, &cliPub)
		if err != nil {
			return
		}
		var servPrivJWK jwk.Key
		var exist bool
		servPrivJWK, exist = jwks.LookupKeyID(cliPub.Params().Name)
		if !exist {
			err = errors.New("key not exist")
			return
		}
		var servPriv ecdsa.PrivateKey
		err = servPrivJWK.Raw(&servPriv)
		if err != nil {
			return
		}
		secret, _ := elliptic.P256().ScalarMult(cliPub.X, cliPub.Y, servPriv.D.Bytes())
		var nonce []byte
		nonce, err = base64.StdEncoding.DecodeString(body["i"].(string))
		if err != nil {
			return
		}
		var ciphertext []byte
		ciphertext, err = base64.StdEncoding.DecodeString(body["c"].(string))
		if err != nil {
			return
		}
		var signature []byte
		signature, err = base64.StdEncoding.DecodeString(body["s"].(string))
		if err != nil {
			return
		}
		var plaintext []byte
		plaintext, err = decrypt(secret.Bytes(), nonce, ciphertext, signature)
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
		var nonce, ciphertext, signature []byte
		nonce, ciphertext, signature, err = encrypt(secret, plaintext)
		if err != nil {
			return
		}
		err = c.JSON(map[string]string{
			"i": base64.StdEncoding.EncodeToString(nonce),
			"c": base64.StdEncoding.EncodeToString(ciphertext),
			"s": base64.StdEncoding.EncodeToString(signature),
		})
		return
	})

	err = app.Listen(":8080")
	if err != nil {
		log.Fatalln(err)
	}
}
