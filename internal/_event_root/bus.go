package event

import (
	"advance-honeypot-network/pkg/types"
	"crypto/rand"
	"fmt"
	"time"
)

// EventBus gère la distribution des événements vers les processeurs
type EventBus struct {
	PublishChan chan types.ProviderEvent // Canal de réception
}

// GlobalBus est l'instance unique accessible par tous les honeypots
var GlobalBus *EventBus

func InitBus() {
	GlobalBus = &EventBus{
		PublishChan: make(chan types.ProviderEvent, 1000), // Buffer de 1000 événements
	}
	// Lance le processeur en tâche de fond (Goroutine)
	go GlobalBus.startProcessing()
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
