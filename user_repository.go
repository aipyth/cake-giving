package main

import (
	"errors"
	"sync"
)

type InMemoryUserStorage struct {
	lock    sync.RWMutex
	storage map[string]User
}

func NewInMemoryStorage() *InMemoryUserStorage {
	return &InMemoryUserStorage{
		lock:    sync.RWMutex{},
		storage: make(map[string]User),
	}
}

// Add should return error if user with given key (login) is already present
func (s *InMemoryUserStorage) Add(key string, u User) error {
	s.lock.Lock()
	if _, ok := s.storage[key]; ok {
		return errors.New("user already exists")
	}
	s.storage[key] = u
	s.lock.Unlock()
	return nil
}

//  Get return User by key if exists
func (s *InMemoryUserStorage) Get(key string) (User, error) {
	u, ok := s.storage[key]
	if !ok {
		return u, errors.New("no such user")
	}
	return u, nil
}

// Update should return error if there is no such user to update
func (s *InMemoryUserStorage) Update(key string, u User) error {
	if _, ok := s.storage[key]; !ok {
		return errors.New("no such user")
	}
	s.storage[key] = u
	return nil
}

// Delete should return error if there is no such user to delete
// Delete should return deleted user
func (s *InMemoryUserStorage) Delete(key string) (User, error) {
	if _, ok := s.storage[key]; !ok {
		return User{}, errors.New("no such user")
	}
	u := s.storage[key]
	delete(s.storage, key)
	return u, nil
}
