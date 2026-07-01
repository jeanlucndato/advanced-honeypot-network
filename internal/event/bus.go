package event

import (
	"advance-honeypot-network/pkg/types"
	"crypto/rand"
	"fmt"
	"sync"
	"time"
)

// EventBus gère la distribution des événements vers les processeurs
type EventBus struct {
	PublishChan chan ProviderEvent // Canal de réception
	subscribers map[chan interface{}]struct{}
	mu          sync.Mutex
}

// GlobalBus est l'instance unique accessible par tous les honeypots
var GlobalBus *EventBus

func InitBus() {
	GlobalBus = &EventBus{
		PublishChan: make(chan ProviderEvent, 1000), // Buffer de 1000 événements
		subscribers: make(map[chan interface{}]struct{}),
	}
	// Lance le processeur en tâche de fond (Goroutine)
	go GlobalBus.startProcessing()
}

func RegisterSubscriber(ch chan interface{}) {
	GlobalBus.mu.Lock()
	defer GlobalBus.mu.Unlock()
	GlobalBus.subscribers[ch] = struct{}{}
}

func UnregisterSubscriber(ch chan interface{}) {
	GlobalBus.mu.Lock()
	defer GlobalBus.mu.Unlock()
	delete(GlobalBus.subscribers, ch)
	close(ch)
}

// L'interface intermédiaire pour tricher un peu sur l'import cyclique
type ProviderEvent interface {
	ToEvent() types.Event
}

func (eb *EventBus) Publish(e types.Event) {
	// Génération d'un faux ID unique rapide pour le dev
	if e.ID == "" {
		e.ID = generateSimpleID()
	}
	e.Timestamp = time.Now()

	// Simulation d'un traitement immédiat avant base de données
	fmt.Printf("\n📢 [EVENT BUS] Nouvel événement reçu ! [%s] IP: %s -> %s (%s)\n", 
		e.Service, e.AttackerIP, e.EventType, e.Payload)

	// Broadcast to subscribers
	eb.mu.Lock()
	defer eb.mu.Unlock()
	for ch := range eb.subscribers {
		select {
		case ch <- e:
		default: // non-blocking if channel is full
		}
	}
}

func (eb *EventBus) startProcessing() {
	// Cette boucle tournera indéfiniment pour traiter les futurs flux
	for range eb.PublishChan {
		// Gestion ultérieure avec Postgres / Redis
	}
}

func generateSimpleID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}
