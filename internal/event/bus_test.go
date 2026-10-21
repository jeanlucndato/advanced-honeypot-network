package event

import (
	"path/filepath"
	"testing"
	"time"

	"advance-honeypot-network/internal/types"
)

func TestSearchJournalAndRetention(t *testing.T) {
	bus := NewBus()
	path := filepath.Join(t.TempDir(), "events.jsonl")
	if err := bus.ConfigureJournal(path); err != nil {
		t.Fatal(err)
	}
	defer bus.journal.Close()
	bus.Publish(types.Event{Timestamp: time.Now().AddDate(0, 0, -10), Service: "ssh", Payload: "old"})
	bus.Publish(types.Event{Timestamp: time.Now(), Service: "http", Payload: "wp-login probe"})
	items, total, err := bus.Search("WP-LOGIN", "http", 10, 0)
	if err != nil || total != 1 || len(items) != 1 || items[0].Service != "http" {
		t.Fatalf("search = %d, %#v, %v", total, items, err)
	}
	if err := bus.ApplyRetention(3); err != nil {
		t.Fatal(err)
	}
	items, total, err = bus.Search("", "", 10, 0)
	if err != nil || total != 1 || items[0].Payload != "wp-login probe" {
		t.Fatalf("post-retention search = %d, %#v, %v", total, items, err)
	}
}
