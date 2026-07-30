package session

import (
	"context"
	"testing"
	"time"
)

func TestSessionActiveState(t *testing.T) {
	ctx := context.Background()
	service := NewService(NewMemoryRepository(), time.Hour)
	current, _, err := service.Create(ctx, "user", "192.0.2.1", "test-agent")
	if err != nil {
		t.Fatal(err)
	}
	active, err := service.IsActive(ctx, current.UserID, current.ID)
	if err != nil || !active {
		t.Fatalf("created session is not active: %v %v", active, err)
	}
	if err := service.Revoke(ctx, current.ID); err != nil {
		t.Fatal(err)
	}
	active, err = service.IsActive(ctx, current.UserID, current.ID)
	if err != nil || active {
		t.Fatalf("revoked session remained active: %v %v", active, err)
	}
}
