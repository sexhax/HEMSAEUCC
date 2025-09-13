package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

type EncryptedMessage struct {
	FromID      string `json:"from_id"`
	ToID        string `json:"to_id"`
	EphemeralPK string `json:"ephemeral_pk"`
	Nonce       string `json:"nonce"`
	Ciphertext  string `json:"ciphertext"`
}

func main() {
	fmt.Println("HEMSAEUCC v1.2 (dev)\n Loaded...")
	if len(os.Args) < 2 {
		fmt.Println("Usage:")
		fmt.Println("  client init")
		fmt.Println("  client send <to_id> <message>")
		fmt.Println("  client fetch")
		fmt.Println("  client id")
		return
	}

	cmd := os.Args[1]
	keysDir := "keys"
	os.MkdirAll(keysDir, 0700)
	privPath := filepath.Join(keysDir, "x25519_secret.bin")
	pubPath := filepath.Join(keysDir, "x25519_public.bin")

if cmd == "init" {
    if _, err := os.Stat(privPath); err == nil {
        fmt.Println("ERROR: Identity already exists. Delete the 'keys' folder to reset.")
        return
    }
    priv := make([]byte, 32)
    rand.Read(priv)
    pub, _ := curve25519.X25519(priv, curve25519.Basepoint)
    os.WriteFile(privPath, priv, 0600)
    os.WriteFile(pubPath, pub, 0600)
    fmt.Println("Your HEMSAEUCC ID:", hex.EncodeToString(pub))
    return
}

	priv, _ := os.ReadFile(privPath)
	pub, _ := os.ReadFile(pubPath)
	myID := hex.EncodeToString(pub)

	switch cmd {
		
case "id":
    if _, err := os.Stat(pubPath); err != nil {
        fmt.Println("No identity found. Run `client init` first.")
        return
    }
    pub, _ := os.ReadFile(pubPath)
    fmt.Println("Your HEMSAEUCC ID:", hex.EncodeToString(pub))
    return

	case "send":
		if len(os.Args) < 4 {
			fmt.Println("client send <to_id> <msg>")
			return
		}
		toID := os.Args[2]
		msg := []byte(os.Args[3])

		ephPriv := make([]byte, 32)
		rand.Read(ephPriv)
		ephPub, _ := curve25519.X25519(ephPriv, curve25519.Basepoint)

		toPub, _ := hex.DecodeString(toID)
		shared, _ := curve25519.X25519(ephPriv, toPub)

		aead, _ := chacha20poly1305.NewX(shared)
		nonce := make([]byte, chacha20poly1305.NonceSizeX)
		rand.Read(nonce)
		ct := aead.Seal(nil, nonce, msg, nil)

		packet := EncryptedMessage{
			FromID:      myID,
			ToID:        toID,
			EphemeralPK: base64.StdEncoding.EncodeToString(ephPub),
			Nonce:       base64.StdEncoding.EncodeToString(nonce),
			Ciphertext:  base64.StdEncoding.EncodeToString(ct),
		}
		pjson, _ := json.Marshal(packet)

		body, _ := json.Marshal(map[string]any{
			"to_id":   toID,
			"from_id": myID,
			"packet":  base64.StdEncoding.EncodeToString(pjson),
		})
		http.Post("http://localhost:8080/send", "application/json", bytes.NewReader(body))
		fmt.Println("Message sent.")

	case "fetch":
		url := fmt.Sprintf("http://localhost:8080/fetch?id=%s", myID)
		resp, _ := http.Get(url)
		defer resp.Body.Close()
		data, _ := io.ReadAll(resp.Body)

		var raw []struct {
			Packet string `json:"packet"`
			FromID string `json:"from_id"`
		}
		json.Unmarshal(data, &raw)

		for _, r := range raw {
			b, _ := base64.StdEncoding.DecodeString(r.Packet)
			var m EncryptedMessage
			json.Unmarshal(b, &m)

			ephPub, _ := base64.StdEncoding.DecodeString(m.EphemeralPK)
			shared, _ := curve25519.X25519(priv, ephPub)
			aead, _ := chacha20poly1305.NewX(shared)
			nonce, _ := base64.StdEncoding.DecodeString(m.Nonce)
			ct, _ := base64.StdEncoding.DecodeString(m.Ciphertext)
			plain, err := aead.Open(nil, nonce, ct, nil)
			if err != nil {
				fmt.Println("Failed to decrypt from", m.FromID[:8])
				continue
			}
			fmt.Printf("[%s]: %s\n", m.FromID[:8], plain)
		}

	default:
		fmt.Println("Unknown command")
	}
}
