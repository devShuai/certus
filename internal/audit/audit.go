package audit

import (
	"context"
	"errors"
	"strings"
	"time"
)

var ErrInvalid = errors.New("invalid audit event")

type Outcome string

const (
	OutcomeSuccess Outcome = "success"
	OutcomeFailure Outcome = "failure"
)

type Event struct {
	ID          string         `json:"id"`
	OccurredAt  time.Time      `json:"occurred_at"`
	ActorUserID *string        `json:"actor_user_id,omitempty"`
	EventType   string         `json:"event_type"`
	ClientID    *string        `json:"client_id,omitempty"`
	IPAddress   string         `json:"ip_address,omitempty"`
	RequestID   string         `json:"request_id,omitempty"`
	Outcome     Outcome        `json:"outcome"`
	Details     map[string]any `json:"details"`
}

type Filter struct {
	ActorUserID string
	EventType   string
	ClientID    string
	Outcome     Outcome
	From        *time.Time
	To          *time.Time
	Limit       int
	Offset      int
}

type Page struct {
	Items  []Event `json:"items"`
	Total  int64   `json:"total"`
	Limit  int     `json:"limit"`
	Offset int     `json:"offset"`
}

type Repository interface {
	Append(context.Context, Event) (Event, error)
	List(context.Context, Filter) (Page, error)
}

func Normalize(event Event, now time.Time) (Event, error) {
	event.EventType = strings.TrimSpace(event.EventType)
	event.IPAddress = strings.TrimSpace(event.IPAddress)
	event.RequestID = strings.TrimSpace(event.RequestID)
	if event.EventType == "" || (event.Outcome != OutcomeSuccess && event.Outcome != OutcomeFailure) {
		return Event{}, ErrInvalid
	}
	if event.OccurredAt.IsZero() {
		event.OccurredAt = now.UTC()
	} else {
		event.OccurredAt = event.OccurredAt.UTC()
	}
	if event.Details == nil {
		event.Details = map[string]any{}
	}
	return event, nil
}
