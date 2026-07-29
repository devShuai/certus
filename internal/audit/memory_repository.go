package audit

import (
	"context"
	"sort"
	"strings"
	"sync"

	"certus/internal/security"
)

type MemoryRepository struct {
	mu     sync.RWMutex
	events []Event
}

func NewMemoryRepository() *MemoryRepository {
	return &MemoryRepository{}
}

func (r *MemoryRepository) Append(_ context.Context, event Event) (Event, error) {
	if event.ID == "" {
		id, err := security.RandomToken(16)
		if err != nil {
			return Event{}, err
		}
		event.ID = id
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, cloneEvent(event))
	return cloneEvent(event), nil
}

func (r *MemoryRepository) List(_ context.Context, filter Filter) (Page, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	items := make([]Event, 0)
	for _, event := range r.events {
		if filter.ActorUserID != "" && (event.ActorUserID == nil || *event.ActorUserID != filter.ActorUserID) {
			continue
		}
		if filter.EventType != "" && !strings.EqualFold(event.EventType, filter.EventType) {
			continue
		}
		if filter.ClientID != "" && (event.ClientID == nil || *event.ClientID != filter.ClientID) {
			continue
		}
		if filter.Outcome != "" && event.Outcome != filter.Outcome {
			continue
		}
		if filter.From != nil && event.OccurredAt.Before(*filter.From) {
			continue
		}
		if filter.To != nil && !event.OccurredAt.Before(*filter.To) {
			continue
		}
		items = append(items, cloneEvent(event))
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].OccurredAt.Equal(items[j].OccurredAt) {
			return items[i].ID > items[j].ID
		}
		return items[i].OccurredAt.After(items[j].OccurredAt)
	})
	total := int64(len(items))
	start := min(filter.Offset, len(items))
	end := min(start+filter.Limit, len(items))
	return Page{Items: items[start:end], Total: total, Limit: filter.Limit, Offset: filter.Offset}, nil
}

func cloneEvent(event Event) Event {
	event.Details = cloneDetails(event.Details)
	if event.ActorUserID != nil {
		value := *event.ActorUserID
		event.ActorUserID = &value
	}
	if event.ClientID != nil {
		value := *event.ClientID
		event.ClientID = &value
	}
	return event
}

func cloneDetails(source map[string]any) map[string]any {
	result := make(map[string]any, len(source))
	for key, value := range source {
		result[key] = value
	}
	return result
}
