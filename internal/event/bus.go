package event

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"advance-honeypot-network/internal/types"
)

// EventBus distributes captured events without letting a slow consumer block
// a honeypot handler. Events are dropped for a subscriber whose buffer is full.
type EventBus struct {
	mu          sync.RWMutex
	subscribers map[chan types.Event]struct{}
	enricher    func(types.Event) types.Event
	history     []types.Event
	dropped     uint64
	capacity    int
	sensorID    string
	journal     *os.File
	journalPath string
	journalSize int64
	journalErrs uint64
}

const maxJournalBytes = 64 << 20

var GlobalBus = NewBus()

func NewBus() *EventBus {
	sensorID := os.Getenv("HIVE_SENSOR_ID")
	if sensorID == "" {
		sensorID = "hive-01"
	}
	return &EventBus{subscribers: make(map[chan types.Event]struct{}), capacity: 1000, sensorID: sensorID}
}

// InitBus remains available for callers that want to reset the process bus.
func InitBus() { GlobalBus = NewBus() }

func (eb *EventBus) SetEnricher(enricher func(types.Event) types.Event) {
	eb.mu.Lock()
	eb.enricher = enricher
	eb.mu.Unlock()
}

func (eb *EventBus) Subscribe(buffer int) chan types.Event {
	if buffer < 1 {
		buffer = 1
	}
	ch := make(chan types.Event, buffer)
	eb.mu.Lock()
	eb.subscribers[ch] = struct{}{}
	eb.mu.Unlock()
	return ch
}

// ConfigureJournal loads the recent event window and appends future events.
func (eb *EventBus) ConfigureJournal(path string) error {
	if dir := filepath.Dir(path); dir != "." {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return err
		}
	}
	load := func(filePath string) error {
		data, err := os.Open(filePath)
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			return err
		}
		scanner := bufio.NewScanner(data)
		scanner.Buffer(make([]byte, 64<<10), 1<<20)
		for scanner.Scan() {
			var item types.Event
			if json.Unmarshal(scanner.Bytes(), &item) == nil {
				eb.history = append(eb.history, item)
				if len(eb.history) > eb.capacity*2 {
					eb.history = eb.history[len(eb.history)-eb.capacity:]
				}
			}
		}
		if err := scanner.Err(); err != nil {
			_ = data.Close()
			return err
		}
		return data.Close()
	}
	if err := load(path + ".1"); err != nil {
		return err
	}
	if err := load(path); err != nil {
		return err
	}
	if len(eb.history) > eb.capacity {
		eb.history = eb.history[len(eb.history)-eb.capacity:]
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return err
	}
	eb.journal, eb.journalPath, eb.journalSize = f, path, info.Size()
	return nil
}

func (eb *EventBus) Unsubscribe(ch chan types.Event) {
	eb.mu.Lock()
	if _, exists := eb.subscribers[ch]; exists {
		delete(eb.subscribers, ch)
		close(ch)
	}
	eb.mu.Unlock()
}

func RegisterSubscriber(ch chan types.Event) {
	GlobalBus.mu.Lock()
	GlobalBus.subscribers[ch] = struct{}{}
	GlobalBus.mu.Unlock()
}

func UnregisterSubscriber(ch chan types.Event) { GlobalBus.Unsubscribe(ch) }

func (eb *EventBus) Publish(e types.Event) {
	if e.ID == "" {
		e.ID = generateSimpleID()
	}
	if e.Timestamp.IsZero() {
		e.Timestamp = time.Now().UTC()
	}
	if e.SensorID == "" {
		e.SensorID = eb.sensorID
	}
	eb.mu.RLock()
	enrich := eb.enricher
	if enrich != nil {
		e = enrich(e)
	}
	eb.mu.RUnlock()
	eb.mu.Lock()
	eb.history = append(eb.history, e)
	if len(eb.history) > eb.capacity {
		copy(eb.history, eb.history[len(eb.history)-eb.capacity:])
		eb.history = eb.history[:eb.capacity]
	}
	for ch := range eb.subscribers {
		select {
		case ch <- e:
		default:
			eb.dropped++
		}
	}
	if eb.journal == nil && eb.journalPath != "" {
		if f, err := os.OpenFile(eb.journalPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600); err == nil {
			if info, statErr := f.Stat(); statErr == nil {
				eb.journal, eb.journalSize = f, info.Size()
			} else {
				_ = f.Close()
				eb.journalErrs++
			}
		} else {
			eb.journalErrs++
		}
	}
	if eb.journal != nil {
		line, err := json.Marshal(e)
		if err != nil {
			eb.journalErrs++
		} else {
			line = append(line, '\n')
			if eb.journalSize+int64(len(line)) > maxJournalBytes {
				if err := eb.rotateJournal(); err != nil {
					eb.journalErrs++
				}
			}
			if eb.journal != nil {
				n, writeErr := eb.journal.Write(line)
				eb.journalSize += int64(n)
				if writeErr != nil || n != len(line) {
					eb.journalErrs++
				}
			}
		}
	} else if eb.journalPath != "" {
		eb.journalErrs++
	}
	eb.mu.Unlock()
}

func (eb *EventBus) rotateJournal() error {
	if eb.journal == nil {
		return fmt.Errorf("event journal is not open")
	}
	if err := eb.journal.Close(); err != nil {
		eb.journal = nil
		return err
	}
	eb.journal = nil
	backup := eb.journalPath + ".1"
	if err := os.Remove(backup); err != nil && !os.IsNotExist(err) {
		return err
	}
	if err := os.Rename(eb.journalPath, backup); err != nil {
		return err
	}
	f, err := os.OpenFile(eb.journalPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	eb.journal, eb.journalSize = f, 0
	return nil
}

// Recent returns a copy of the newest events, newest first.
func (eb *EventBus) Recent(limit int) []types.Event {
	eb.mu.RLock()
	defer eb.mu.RUnlock()
	if limit <= 0 || limit > len(eb.history) {
		limit = len(eb.history)
	}
	out := make([]types.Event, limit)
	for i := 0; i < limit; i++ {
		out[i] = eb.history[len(eb.history)-1-i]
	}
	return out
}

func (eb *EventBus) Stats() (subscribers int, dropped uint64, journalErrors uint64) {
	eb.mu.RLock()
	defer eb.mu.RUnlock()
	return len(eb.subscribers), eb.dropped, eb.journalErrs
}

func (eb *EventBus) SensorID() string { return eb.sensorID }

func generateSimpleID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return time.Now().UTC().Format("20060102150405.000000000")
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	h := hex.EncodeToString(b)
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

func GenerateSimpleIDForStore() string { return generateSimpleID() }
