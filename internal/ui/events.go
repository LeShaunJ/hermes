package ui

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/leshaunj/hermes/internal/db"
)

// eventHub fans a single inbound stream of db.Events out to every browser
// currently connected to /events.  Slow subscribers drop events rather than
// stalling the upstream listener; the SSE feed is a live tail, not a queue.
type eventHub struct {
	mu     sync.Mutex
	subs   map[chan *db.Event]struct{}
	closed bool
}

func newEventHub() *eventHub {
	return &eventHub{subs: make(map[chan *db.Event]struct{})}
}

// run consumes events from in and broadcasts each to every subscriber.
// Returns when in is closed.
func (h *eventHub) run(in <-chan *db.Event) {
	for ev := range in {
		h.broadcast(ev)
	}
}

func (h *eventHub) broadcast(ev *db.Event) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for ch := range h.subs {
		select {
		case ch <- ev:
		default:
			// subscriber too slow — drop this event for this client only.
		}
	}
}

func (h *eventHub) subscribe() chan *db.Event {
	ch := make(chan *db.Event, 16)
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		close(ch)
		return ch
	}
	h.subs[ch] = struct{}{}
	return ch
}

func (h *eventHub) unsubscribe(ch chan *db.Event) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if _, ok := h.subs[ch]; ok {
		delete(h.subs, ch)
		close(ch)
	}
}

func (h *eventHub) close() {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return
	}
	h.closed = true
	for ch := range h.subs {
		delete(h.subs, ch)
		close(ch)
	}
}

// serveEvents upgrades the request to a Server-Sent Events stream.  Each
// db.Event is encoded as JSON and written as a single SSE message.  The
// stream ends when the client disconnects.
//
// Heartbeat comments (`: ping`) are written every 30 s so intermediate
// proxies do not idle-close the connection.
func (s *Server) serveEvents(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no") // disable nginx buffering
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	ch := s.hub.subscribe()
	defer s.hub.unsubscribe(ch)

	heartbeat := time.NewTicker(30 * time.Second)
	defer heartbeat.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case ev, ok := <-ch:
			if !ok {
				return
			}
			if err := writeSSE(w, ev); err != nil {
				return
			}
			flusher.Flush()
		case <-heartbeat.C:
			if _, err := fmt.Fprint(w, ": ping\n\n"); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}

// writeSSE encodes ev as a single SSE message with the named event type
// "event" so htmx's sse-swap="event" picks it up.
func writeSSE(w http.ResponseWriter, ev *db.Event) error {
	payload, err := json.Marshal(sseEventPayload{
		ID:        ev.ID,
		ImageID:   ev.ImageID,
		Source:    string(ev.Source),
		EventType: ev.EventType,
		Details:   ev.Details,
		CreatedAt: ev.CreatedAt,
	})
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(w, "event: event\ndata: %s\n\n", payload)
	return err
}

type sseEventPayload struct {
	ID        int64     `json:"id"`
	ImageID   *int64    `json:"image_id,omitempty"`
	Source    string    `json:"source"`
	EventType string    `json:"event_type"`
	Details   string    `json:"details,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}
