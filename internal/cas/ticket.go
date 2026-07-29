package cas

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"time"
)

var (
	ErrTicketNotFound = errors.New("service ticket not found")
	ErrTicketExpired  = errors.New("service ticket expired")
)

type ServiceTicket struct {
	Hash               []byte
	Ticket             string
	ClientID           string
	Service            string
	UserID             string
	SessionID          string
	PrimaryCredentials bool
	IssuedAt           time.Time
	ExpiresAt          time.Time
}

type ServiceSession struct {
	SessionID string
	ClientID  string
	Service   string
	Ticket    string
}

type Repository interface {
	SaveServiceTicket(context.Context, ServiceTicket) error
	ConsumeServiceTicket(context.Context, []byte, string, bool, time.Time) (ServiceTicket, error)
	ListServiceSessions(context.Context, string) ([]ServiceSession, error)
	DeleteServiceSessions(context.Context, string) error
}

type memoryTicket struct {
	ServiceTicket
	consumedAt *time.Time
}

type MemoryRepository struct {
	mu       sync.Mutex
	tickets  []memoryTicket
	sessions []ServiceSession
}

func NewMemoryRepository() *MemoryRepository {
	return &MemoryRepository{}
}

func (r *MemoryRepository) SaveServiceTicket(_ context.Context, value ServiceTicket) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	value.Hash = append([]byte(nil), value.Hash...)
	r.tickets = append(r.tickets, memoryTicket{ServiceTicket: value})
	r.sessions = append(r.sessions, ServiceSession{
		SessionID: value.SessionID,
		ClientID:  value.ClientID,
		Service:   value.Service,
		Ticket:    value.Ticket,
	})
	return nil
}

func (r *MemoryRepository) ConsumeServiceTicket(_ context.Context, hash []byte, service string, requirePrimary bool, now time.Time) (ServiceTicket, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for index := range r.tickets {
		record := &r.tickets[index]
		if !bytes.Equal(record.Hash, hash) || record.Service != service {
			continue
		}
		if record.consumedAt != nil {
			return ServiceTicket{}, ErrTicketNotFound
		}
		if requirePrimary && !record.PrimaryCredentials {
			return ServiceTicket{}, ErrTicketNotFound
		}
		if !record.ExpiresAt.After(now) {
			return ServiceTicket{}, ErrTicketExpired
		}
		record.consumedAt = &now
		value := record.ServiceTicket
		value.Hash = append([]byte(nil), value.Hash...)
		return value, nil
	}
	return ServiceTicket{}, ErrTicketNotFound
}

func (r *MemoryRepository) ListServiceSessions(_ context.Context, sessionID string) ([]ServiceSession, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	result := make([]ServiceSession, 0)
	for _, value := range r.sessions {
		if value.SessionID == sessionID {
			result = append(result, value)
		}
	}
	return result, nil
}

func (r *MemoryRepository) DeleteServiceSessions(_ context.Context, sessionID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	result := r.sessions[:0]
	for _, value := range r.sessions {
		if value.SessionID != sessionID {
			result = append(result, value)
		}
	}
	r.sessions = result
	return nil
}
