package audit

import (
	"context"
	"testing"
	"time"
)

func TestMemoryRepositoryFiltersAndPagesEvents(t *testing.T) {
	repository := NewMemoryRepository()
	now := time.Date(2026, 7, 29, 1, 2, 3, 0, time.UTC)
	userID := "user-1"
	for _, eventType := range []string{"login.password", "session.revoked"} {
		event, err := Normalize(Event{
			ActorUserID: &userID,
			EventType:   eventType,
			Outcome:     OutcomeSuccess,
		}, now)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := repository.Append(context.Background(), event); err != nil {
			t.Fatal(err)
		}
		now = now.Add(time.Second)
	}
	page, err := repository.List(context.Background(), Filter{
		ActorUserID: userID,
		EventType:   "session.revoked",
		Limit:       20,
	})
	if err != nil {
		t.Fatal(err)
	}
	if page.Total != 1 || len(page.Items) != 1 || page.Items[0].EventType != "session.revoked" {
		t.Fatalf("unexpected audit page: %#v", page)
	}
}
