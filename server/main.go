package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	bolt "go.etcd.io/bbolt"
)

const (
	dbFile     = "messages.db"
	bucketMsgs = "msgs"
)

type StoredMessage struct {
	ToID   string `json:"to_id"`
	FromID string `json:"from_id"`
	Packet string `json:"packet"`
	TS     int64  `json:"ts"`
}

func main() {
	db, err := bolt.Open(dbFile, 0600, nil)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	db.Update(func(tx *bolt.Tx) error {
		_, _ = tx.CreateBucketIfNotExists([]byte(bucketMsgs))
		return nil
	})

	http.HandleFunc("/send", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", 405)
			return
		}
		var m StoredMessage
		if err := json.NewDecoder(r.Body).Decode(&m); err != nil {
			http.Error(w, "bad json", 400)
			return
		}
		m.TS = time.Now().Unix()
		err := db.Update(func(tx *bolt.Tx) error {
			b := tx.Bucket([]byte(bucketMsgs))
			id := fmt.Sprintf("%s-%d", m.ToID, time.Now().UnixNano())
			data, _ := json.Marshal(m)
			return b.Put([]byte(id), data)
		})
		if err != nil {
			http.Error(w, "db error", 500)
			return
		}
		w.Write([]byte(`{"ok":true}`))
	})

	http.HandleFunc("/fetch", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "GET only", 405)
			return
		}
		toID := r.URL.Query().Get("id")
		if toID == "" {
			http.Error(w, "missing id", 400)
			return
		}

		var results []StoredMessage
		_ = db.Update(func(tx *bolt.Tx) error {
			b := tx.Bucket([]byte(bucketMsgs))
			c := b.Cursor()
			for k, v := c.First(); k != nil; k, v = c.Next() {
				if len(k) >= len(toID) && string(k[:len(toID)]) == toID {
					var m StoredMessage
					_ = json.Unmarshal(v, &m)
					results = append(results, m)
					c.Delete()
				}
			}
			return nil
		})
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(results)
	})

	fmt.Println("HEMSAEUCC relay running on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
