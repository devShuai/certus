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

type ProxyGrantingTicket struct {
	Hash               []byte
	ClientID           string
	UserID             string
	SessionID          string
	CallbackURL        string
	Proxies            []string
	PrimaryCredentials bool
	IssuedAt           time.Time
	ExpiresAt          time.Time
}

type ProxyTicket struct {
	Hash               []byte
	ClientID           string
	TargetService      string
	UserID             string
	SessionID          string
	Proxies            []string
	PrimaryCredentials bool
	IssuedAt           time.Time
	ExpiresAt          time.Time
}

type Repository interface {
	SaveServiceTicket(context.Context, ServiceTicket) error
	ConsumeServiceTicket(context.Context, []byte, string, bool, time.Time) (ServiceTicket, error)
	SaveProxyGrantingTicket(context.Context, ProxyGrantingTicket) error
	FindProxyGrantingTicket(context.Context, []byte, time.Time) (ProxyGrantingTicket, error)
	SaveProxyTicket(context.Context, ProxyTicket, []byte) error
	ConsumeProxyTicket(context.Context, []byte, string, bool, time.Time) (ProxyTicket, error)
	ListServiceSessions(context.Context, string) ([]ServiceSession, error)
	DeleteServiceSessions(context.Context, string) error
}

type memoryTicket struct {
	ServiceTicket
	consumedAt *time.Time
}

type memoryProxyTicket struct {
	ProxyTicket
	consumedAt *time.Time
}

type MemoryRepository struct {
	mu                   sync.Mutex
	tickets              []memoryTicket
	proxyGrantingTickets []ProxyGrantingTicket
	proxyTickets         []memoryProxyTicket
	sessions             []ServiceSession
}

func NewMemoryRepository() *MemoryRepository {
	return &MemoryRepository{}
}

func (r *MemoryRepository) SaveProxyGrantingTicket(_ context.Context, value ProxyGrantingTicket) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	value.Hash = append([]byte(nil), value.Hash...)
	value.Proxies = append([]string(nil), value.Proxies...)
	r.proxyGrantingTickets = append(r.proxyGrantingTickets, value)
	return nil
}

func (r *MemoryRepository) FindProxyGrantingTicket(_ context.Context, hash []byte, now time.Time) (ProxyGrantingTicket, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, record := range r.proxyGrantingTickets {
		if !bytes.Equal(record.Hash, hash) {
			continue
		}
		if !record.ExpiresAt.After(now) {
			return ProxyGrantingTicket{}, ErrTicketExpired
		}
		record.Hash = append([]byte(nil), record.Hash...)
		record.Proxies = append([]string(nil), record.Proxies...)
		return record, nil
	}
	return ProxyGrantingTicket{}, ErrTicketNotFound
}

func (r *MemoryRepository) SaveProxyTicket(_ context.Context, value ProxyTicket, pgtHash []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	found := false
	for _, pgt := range r.proxyGrantingTickets {
		if bytes.Equal(pgt.Hash, pgtHash) {
			found = true
			break
		}
	}
	if !found {
		return ErrTicketNotFound
	}
	value.Hash = append([]byte(nil), value.Hash...)
	value.Proxies = append([]string(nil), value.Proxies...)
	r.proxyTickets = append(r.proxyTickets, memoryProxyTicket{ProxyTicket: value})
	return nil
}

func (r *MemoryRepository) ConsumeProxyTicket(_ context.Context, hash []byte, targetService string, requirePrimary bool, now time.Time) (ProxyTicket, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for index := range r.proxyTickets {
		record := &r.proxyTickets[index]
		if !bytes.Equal(record.Hash, hash) || record.TargetService != targetService {
			continue
		}
		if record.consumedAt != nil {
			return ProxyTicket{}, ErrTicketNotFound
		}
		if requirePrimary && !record.PrimaryCredentials {
			return ProxyTicket{}, ErrTicketNotFound
		}
		if !record.ExpiresAt.After(now) {
			return ProxyTicket{}, ErrTicketExpired
		}
		record.consumedAt = &now
		value := record.ProxyTicket
		value.Hash = append([]byte(nil), value.Hash...)
		value.Proxies = append([]string(nil), value.Proxies...)
		return value, nil
	}
	return ProxyTicket{}, ErrTicketNotFound
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
	pgts := r.proxyGrantingTickets[:0]
	for _, value := range r.proxyGrantingTickets {
		if value.SessionID != sessionID {
			pgts = append(pgts, value)
		}
	}
	r.proxyGrantingTickets = pgts
	proxyTickets := r.proxyTickets[:0]
	for _, value := range r.proxyTickets {
		if value.SessionID != sessionID {
			proxyTickets = append(proxyTickets, value)
		}
	}
	r.proxyTickets = proxyTickets
	return nil
}
