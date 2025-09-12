//go:build windows

package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sync"

	"github.com/jchv/go-webview2"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

// EncryptedMessage represents the data structure for an encrypted message packet.
type EncryptedMessage struct {
	FromID      string `json:"from_id"`
	ToID        string `json:"to_id"`
	EphemeralPK string `json:"ephemeral_pk"`
	Nonce       string `json:"nonce"`
	Ciphertext  string `json:"ciphertext"`
}

// ClientState holds the state of the chat client, including keys, contacts, and message history.
type ClientState struct {
	myID            string
	privKey         []byte
	pubKey          []byte
	activeContactID string
	contacts        []string
	messageHistory  map[string][]string
	mu              sync.Mutex
	w               webview2.WebView
}

const (
	keysDir  = "keys"
	privPath = "keys/x25519_secret.bin"
	pubPath  = "keys/x25519_public.bin"
)

// The HTML for the chat client's user interface.
const html = `<!DOCTYPE html>
<html>
<head>
	<title>Go Chat Client</title>
	<style>
		body {
			font-family: Arial, sans-serif;
			margin: 0;
			padding: 0;
			display: flex;
			height: 100vh;
			background-color: #f0f2f5;
		}
		.sidebar {
			width: 250px;
			background-color: #ffffff;
			border-right: 1px solid #e0e0e0;
			display: flex;
			flex-direction: column;
			padding: 10px;
		}
		.main-content {
			flex-grow: 1;
			display: flex;
			flex-direction: column;
		}
		.header {
			padding: 15px;
			background-color: #007bff;
			color: white;
			display: flex;
			justify-content: space-between;
			align-items: center;
		}
		.chat-area {
			flex-grow: 1;
			padding: 20px;
			overflow-y: auto;
			background-color: #e5e5e5;
		}
		.message-input {
			padding: 10px;
			background-color: #ffffff;
			display: flex;
			border-top: 1px solid #e0e0e0;
		}
		.message-input input {
			flex-grow: 1;
			border: 1px solid #ccc;
			padding: 8px;
			border-radius: 5px;
		}
		.message-input button {
			margin-left: 10px;
			background-color: #007bff;
			color: white;
			border: none;
			padding: 8px 15px;
			border-radius: 5px;
			cursor: pointer;
		}
		.contact-list {
			list-style-type: none;
			padding: 0;
			margin: 0;
			flex-grow: 1;
			overflow-y: auto;
		}
		.contact-item {
			padding: 10px;
			cursor: pointer;
			border-bottom: 1px solid #eee;
		}
		.contact-item:hover {
			background-color: #f0f0f0;
		}
		.contact-item.active {
			background-color: #d1e7ff;
			font-weight: bold;
		}
		.message {
			margin-bottom: 10px;
			padding: 8px;
			border-radius: 5px;
		}
		.message.sent {
			text-align: right;
			background-color: #d1e7ff;
			margin-left: auto;
			max-width: 70%;
		}
		.message.received {
			text-align: left;
			background-color: #ffffff;
			margin-right: auto;
			max-width: 70%;
		}
		.your-id-label {
			padding: 10px;
			text-align: center;
			font-size: 14px;
			color: #555;
			word-break: break-all;
		}
		.contact-form {
			display: flex;
			gap: 5px;
			margin-top: 10px;
			margin-bottom: 10px;
		}
		.contact-form input {
			flex-grow: 1;
			padding: 8px;
			border: 1px solid #ccc;
			border-radius: 5px;
		}
		.contact-form button {
			background-color: #28a745;
			color: white;
			border: none;
			padding: 8px 15px;
			border-radius: 5px;
			cursor: pointer;
		}
	</style>
</head>
<body>
	<div class="sidebar">
		<div class="your-id-label" id="my-id-label">Your ID: Not Set</div>
		<div class="contact-form">
			<input type="text" id="contact-entry" placeholder="Enter contact ID">
			<button onclick="addContact()">Add</button>
		</div>
		<ul id="contact-list" class="contact-list"></ul>
	</div>
	<div class="main-content">
		<div class="header">
			<h3 id="chat-title">Select a chat to begin</h3>
		</div>
		<div class="chat-area" id="chat-area"></div>
		<div class="message-input">
			<input type="text" id="message-input" placeholder="Type your message here...">
			<button onclick="sendMessage()">Send</button>
		</div>
	</div>

	<script>
		let myId = "";
		let activeContactId = "";
		let contactNames = {};

		window.onload = async function() {
			const idExists = await window.go_is_id_existing();
			if (!idExists) {
				const myId = await window.go_init_identity();
				// Changed from alert() to a UI update for better user experience
				document.getElementById('my-id-label').textContent = "Your ID: " + myId;
			} else {
				myId = await window.go_get_my_id();
				document.getElementById('my-id-label').textContent = "Your ID: " + myId.substring(0, 8);
			}
			fetchMessages();
			// Polling interval changed from 5000ms to 2000ms (2 seconds)
			setInterval(fetchMessages, 2000);
		};

		async function addContact() {
			const contactId = document.getElementById('contact-entry').value;
			if (contactId) {
				await window.go_add_contact(contactId);
				document.getElementById('contact-entry').value = "";
				updateContactList();
			}
		}

		async function updateContactList() {
			const contacts = await window.go_get_contacts();
			const list = document.getElementById('contact-list');
			list.innerHTML = '';
			contactNames = {};
			contacts.forEach((contactId, index) => {
				const li = document.createElement('li');
				li.className = 'contact-item';
				li.textContent = contactId.substring(0, 8);
				contactNames[contactId.substring(0, 8)] = contactId;
				li.onclick = () => {
					selectChat(contactId);
					document.querySelectorAll('.contact-item').forEach(item => item.classList.remove('active'));
					li.classList.add('active');
				};
				list.appendChild(li);
			});
		}

		async function selectChat(contactId) {
			activeContactId = contactId;
			document.getElementById('chat-title').textContent = "Chat with " + contactId.substring(0, 8);
			const chatArea = document.getElementById('chat-area');
			chatArea.innerHTML = '';
			const messages = await window.go_get_history(contactId);
			messages.forEach(msg => {
				const p = document.createElement('p');
				p.className = 'message ' + (msg.startsWith('[You]') ? 'sent' : 'received');
				p.textContent = msg;
				chatArea.appendChild(p);
			});
			chatArea.scrollTop = chatArea.scrollHeight;
		}

		async function sendMessage() {
			const input = document.getElementById('message-input');
			const message = input.value;
			if (message && activeContactId) {
				await window.go_send_message(activeContactId, message);
				const chatArea = document.getElementById('chat-area');
				const p = document.createElement('p');
				p.className = 'message sent';
				p.textContent = "[You]: " + message;
				chatArea.appendChild(p);
				chatArea.scrollTop = chatArea.scrollHeight;
				input.value = "";
			}
		}

		async function fetchMessages() {
			const newMessages = await window.go_fetch_messages();
			if (newMessages) {
				newMessages.forEach(msg => {
					if (!contactNames[msg.FromID.substring(0, 8)]) {
						window.go_add_contact(msg.FromID);
						updateContactList();
					}
					if (msg.FromID === activeContactId) {
						const chatArea = document.getElementById('chat-area');
						const p = document.createElement('p');
						p.className = 'message received';
						p.textContent = '[' + msg.FromID.substring(0, 8) + ']: ' + msg.Ciphertext;
						chatArea.appendChild(p);
						chatArea.scrollTop = chatArea.scrollHeight;
					}
				});
			}
		}
	</script>
</body>
</html>`

// initIdentity generates a new key pair and saves it to a file.
func (cs *ClientState) initIdentity() (string, error) {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	// Check if identity already exists.
	if _, err := os.Stat(privPath); err == nil {
		return "", fmt.Errorf("identity already exists. Delete the 'keys' folder to reset.")
	}

	// Generate a new private key.
	priv := make([]byte, 32)
	if _, err := rand.Read(priv); err != nil {
		return "", fmt.Errorf("failed to generate random private key: %w", err)
	}

	// Derive the public key from the private key.
	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		return "", fmt.Errorf("failed to derive public key: %w", err)
	}

	// Create a directory for the keys and save them.
	if err := os.MkdirAll(keysDir, 0700); err != nil {
		return "", fmt.Errorf("failed to create keys directory: %w", err)
	}
	if err := os.WriteFile(privPath, priv, 0600); err != nil {
		return "", fmt.Errorf("failed to save private key: %w", err)
	}
	if err := os.WriteFile(pubPath, pub, 0600); err != nil {
		return "", fmt.Errorf("failed to save public key: %w", err)
	}

	cs.privKey = priv
	cs.pubKey = pub
	cs.myID = hex.EncodeToString(pub)
	cs.contacts = []string{}
	cs.messageHistory = make(map[string][]string)

	return cs.myID, nil
}

// loadIdentity loads an existing key pair from a file.
func (cs *ClientState) loadIdentity() error {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	priv, err := os.ReadFile(privPath)
	if err != nil {
		return err
	}
	pub, err := os.ReadFile(pubPath)
	if err != nil {
		return err
	}

	cs.privKey = priv
	cs.pubKey = pub
	cs.myID = hex.EncodeToString(pub)
	cs.contacts = []string{}
	cs.messageHistory = make(map[string][]string)
	return nil
}

// sendMessage encrypts a message and sends it to the server.
func (cs *ClientState) sendMessage(toID, msg string) error {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	// Generate an ephemeral key pair for forward secrecy.
	ephPriv := make([]byte, 32)
	rand.Read(ephPriv)
	ephPub, err := curve25519.X25519(ephPriv, curve25519.Basepoint)
	if err != nil {
		return fmt.Errorf("failed to generate ephemeral key: %w", err)
	}

	toPub, err := hex.DecodeString(toID)
	if err != nil {
		return fmt.Errorf("invalid recipient ID format: %w", err)
	}

	// Derive the shared secret.
	shared, err := curve25519.X25519(ephPriv, toPub)
	if err != nil {
		return fmt.Errorf("failed to derive shared secret: %w", err)
	}

	// Create a ChaCha20-Poly1305 AEAD cipher.
	aead, err := chacha20poly1305.NewX(shared)
	if err != nil {
		return fmt.Errorf("failed to create AEAD: %w", err)
	}

	// Generate a random nonce and seal the message.
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	rand.Read(nonce)
	ct := aead.Seal(nil, nonce, []byte(msg), nil)

	// Build the encrypted message packet.
	packet := EncryptedMessage{
		FromID:      cs.myID,
		ToID:        toID,
		EphemeralPK: base64.StdEncoding.EncodeToString(ephPub),
		Nonce:       base64.StdEncoding.EncodeToString(nonce),
		Ciphertext:  base64.StdEncoding.EncodeToString(ct),
	}
	pjson, err := json.Marshal(packet)
	if err != nil {
		return fmt.Errorf("failed to marshal packet: %w", err)
	}

	body, err := json.Marshal(map[string]any{
		"to_id":   toID,
		"from_id": cs.myID,
		"packet":  base64.StdEncoding.EncodeToString(pjson),
	})
	if err != nil {
		return fmt.Errorf("failed to marshal request body: %w", err)
	}

	// Send the encrypted message to the server.
	_, err = http.Post(fmt.Sprintf("%s/send", "http://localhost:8080"), "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to send message to server: %w", err)
	}

	return nil
}

// fetchMessages retrieves and decrypts messages from the server.
func (cs *ClientState) fetchMessages() ([]EncryptedMessage, error) {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	url := fmt.Sprintf("%s/fetch?id=%s", "http://localhost:8080", cs.myID)
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch messages: %w", err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	var raw []struct {
		Packet string `json:"packet"`
		FromID string `json:"from_id"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	var decryptedMessages []EncryptedMessage
	for _, r := range raw {
		b, err := base64.StdEncoding.DecodeString(r.Packet)
		if err != nil {
			continue
		}
		var m EncryptedMessage
		if err := json.Unmarshal(b, &m); err != nil {
			continue
		}

		ephPub, err := base64.StdEncoding.DecodeString(m.EphemeralPK)
		if err != nil {
			continue
		}

		// Derive the shared secret using our private key and the sender's ephemeral public key.
		shared, err := curve25519.X25519(cs.privKey, ephPub)
		if err != nil {
			continue
		}

		aead, err := chacha20poly1305.NewX(shared)
		if err != nil {
			continue
		}

		nonce, err := base64.StdEncoding.DecodeString(m.Nonce)
		if err != nil {
			continue
		}

		ct, err := base64.StdEncoding.DecodeString(m.Ciphertext)
		if err != nil {
			continue
		}

		// Open the sealed message.
		plain, err := aead.Open(nil, nonce, ct, nil)
		if err != nil {
			log.Printf("Failed to decrypt message from %s: %v\n", m.FromID[:8], err)
			continue
		}
		m.Ciphertext = string(plain)
		decryptedMessages = append(decryptedMessages, m)
	}

	return decryptedMessages, nil
}

// isIDExisting checks if the client has an existing identity.
func (cs *ClientState) isIDExisting() bool {
	return cs.myID != ""
}

// getMyID returns the client's public ID.
func (cs *ClientState) getMyID() string {
	return cs.myID
}

// getContacts returns the list of contacts.
func (cs *ClientState) getContacts() []string {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	return cs.contacts
}

// getHistory returns the message history for a specific contact.
func (cs *ClientState) getHistory(contactID string) []string {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	return cs.messageHistory[contactID]
}

// addContact adds a new contact to the client's contact list.
func (cs *ClientState) addContact(contactID string) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	cs.contacts = append(cs.contacts, contactID)
	cs.messageHistory[contactID] = []string{}
}

func main() {
	cs := &ClientState{}

	// Attempt to load an existing identity.
	if err := cs.loadIdentity(); err != nil {
		log.Println("No existing identity found. A new one will be generated on UI.")
	}

	w := webview2.New(true)
	defer w.Destroy()

	w.SetTitle("HEMSAEUCC - Humanized Encrypted Messaging System Against Europian Union Chat Control")
	w.SetSize(800, 600, webview2.HintNone)

	// Bind Go functions to JavaScript.
	w.Bind("go_is_id_existing", cs.isIDExisting)
	w.Bind("go_init_identity", cs.initIdentity)
	w.Bind("go_get_my_id", cs.getMyID)
	w.Bind("go_add_contact", cs.addContact)
	w.Bind("go_get_contacts", cs.getContacts)
	w.Bind("go_send_message", func(contactID, msg string) {
		err := cs.sendMessage(contactID, msg)
		if err != nil {
			log.Println("Error sending message:", err)
		}
		cs.mu.Lock()
		// Append the sent message to our local history.
		cs.messageHistory[contactID] = append(cs.messageHistory[contactID], "[You]: "+msg)
		cs.mu.Unlock()
	})
	w.Bind("go_fetch_messages", cs.fetchMessages)
	w.Bind("go_get_history", cs.getHistory)

	w.SetHtml(html)
	w.Run()
}
