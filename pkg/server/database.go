package server

import "github.com/jhaals/yopass/pkg/yopass"

// Database is the persistence interface for secret metadata.
//
// Get is a destructive read for one-time secrets: implementations must delete
// the underlying record before returning when the stored Secret has
// OneTime=true. Status is the non-destructive counterpart used to make
// authorization decisions before consumption.
type Database interface {
	Get(key string) (yopass.Secret, error)
	Put(key string, secret yopass.Secret) error
	Delete(key string) (bool, error)
	Status(key string) (yopass.Secret, error)
	Health() error
}
