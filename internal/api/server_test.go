package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestTokenAuthProtectsAPIButAcceptsWebSocketProtocol(t *testing.T) {
	endpoint := tokenAuth("test-token")(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	request := httptest.NewRequest(http.MethodGet, "/api/events", nil)
	response := httptest.NewRecorder()
	endpoint.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("without token status=%d", response.Code)
	}
	request = httptest.NewRequest(http.MethodGet, "/api/events", nil)
	request.Header.Set("Authorization", "Bearer test-token")
	response = httptest.NewRecorder()
	endpoint.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent {
		t.Fatalf("with token status=%d", response.Code)
	}
	request = httptest.NewRequest(http.MethodGet, "/ws/events", nil)
	request.Header.Set("Sec-WebSocket-Protocol", "hive-auth.test-token")
	response = httptest.NewRecorder()
	endpoint.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent {
		t.Fatalf("websocket token status=%d", response.Code)
	}
}
