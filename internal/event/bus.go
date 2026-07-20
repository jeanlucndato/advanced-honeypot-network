package event

import (
	"advance-honeypot-network/internal/types"
	"crypto/rand"
	"fmt"
	"time"
)

// EventBus gère la distribution des événements vers les processeurs de manière purement Lock-Free
type EventBus struct {
	PublishChan chan ProviderEvent
	addChan     chan chan interface{}
	removeChan  chan chan interface{}
}

// GlobalBus est l'instance unique accessible par tous les honeypots
var GlobalBus *EventBus

func InitBus() {
	GlobalBus = &EventBus{
		PublishChan: make(chan ProviderEvent, 5000), // Buffer large pour haute performance
		addChan:     make(chan chan interface{}),
		removeChan:  make(chan chan interface{}),
	}
	// Lance le routeur d'événements 100% Lock-Free (Goroutine)
	go GlobalBus.startProcessing()
}

func RegisterSubscriber(ch chan interface{}) {
	GlobalBus.addChan <- ch
}

func UnregisterSubscriber(ch chan interface{}) {
	GlobalBus.removeChan <- ch
}

type ProviderEvent interface {
	ToEvent() types.Event
}

func (eb *EventBus) Publish(e types.Event) {
	if e.ID == "" {
		e.ID = generateSimpleID()
	}
	e.Timestamp = time.Now()

	fmt.Printf("\n📢 [EVENT BUS] Nouvel événement ! [%s] IP: %s -> %s (%s)\n",
		e.Service, e.AttackerIP, e.EventType, e.Payload)

	// Encapsulation dans un wrapper pour respecter l'interface
	eb.PublishChan <- eventWrapper{e}
}

type eventWrapper struct {
	Event types.Event
}

// Implémentation du ProviderEvent pour la structure anonyme
func (w eventWrapper) ToEvent() types.Event {
	return w.Event
}

func (eb *EventBus) startProcessing() {
	subscribers := make(map[chan interface{}]bool)

	for {
		select {
		case ch := <-eb.addChan:
			subscribers[ch] = true
		case ch := <-eb.removeChan:
			delete(subscribers, ch)
			close(ch)
		case rawEvent := <-eb.PublishChan:
			e := rawEvent.ToEvent()
			for ch := range subscribers {
				select {
				case ch <- e: // Envoi non-bloquant
				default:
					// Si le buffer du souscripteur est plein, on ignore pour éviter le blocage
				}
			}
		}
	}
}

func generateSimpleID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}

func GenerateSimpleIDForStore() string {
	return generateSimpleID()
}
