package client

import (
	"context"
	"errors"
	"net/url"
	"slices"
)

var ErrNotFound = errors.New("client not found")

type LoginMethod string

const (
	LoginPassword LoginMethod = "password"
	LoginLDAP     LoginMethod = "ldap"
	LoginOIDC     LoginMethod = "oidc"
)

type Client struct {
	ID           string        `json:"id"`
	Name         string        `json:"name"`
	Description  string        `json:"description,omitempty"`
	RedirectURIs []string      `json:"redirect_uris"`
	LoginMethods []LoginMethod `json:"login_methods"`
	Enabled      bool          `json:"enabled"`
}

func (c Client) AllowsRedirectURI(candidate string) bool {
	parsed, err := url.Parse(candidate)
	if err != nil || !parsed.IsAbs() || parsed.Fragment != "" {
		return false
	}
	return slices.Contains(c.RedirectURIs, candidate)
}

type Repository interface {
	List(context.Context) ([]Client, error)
	Find(context.Context, string) (Client, error)
}

type MemoryRepository struct {
	clients map[string]Client
	order   []string
}

func NewMemoryRepository(clients ...Client) *MemoryRepository {
	repository := &MemoryRepository{clients: make(map[string]Client), order: make([]string, 0, len(clients))}
	for _, item := range clients {
		repository.clients[item.ID] = clone(item)
		repository.order = append(repository.order, item.ID)
	}
	return repository
}

func (r *MemoryRepository) List(_ context.Context) ([]Client, error) {
	result := make([]Client, 0, len(r.order))
	for _, id := range r.order {
		result = append(result, clone(r.clients[id]))
	}
	return result, nil
}

func (r *MemoryRepository) Find(_ context.Context, id string) (Client, error) {
	item, ok := r.clients[id]
	if !ok {
		return Client{}, ErrNotFound
	}
	return clone(item), nil
}

func clone(item Client) Client {
	item.RedirectURIs = slices.Clone(item.RedirectURIs)
	item.LoginMethods = slices.Clone(item.LoginMethods)
	return item
}
