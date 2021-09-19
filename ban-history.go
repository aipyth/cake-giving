package main

import "time"

type BanRecord struct {
	Time   time.Time
	From   User
	To     User
	Action string
	Reason string
}

type BanHistoryRepository interface {
	AddBanned(from User, to User, reason string) error
	AddUnbanned(from User, to User, reason string) error
	GetUserBanHistory(user User) ([]BanRecord, error)
}

type InMemoryBanHistory struct {
	storage map[User][]BanRecord
}

func NewInMemoryBanHistory() *InMemoryBanHistory {
	return &InMemoryBanHistory{
		storage: make(map[User][]BanRecord),
	}
}

func (b *InMemoryBanHistory) AddBanned(from User, to User, reason string) error {
	record := BanRecord{
		Time:   time.Now(),
		From:   from,
		To:     to,
		Action: "ban",
		Reason: reason,
	}
	if b.storage[to] == nil {
		b.storage[to] = make([]BanRecord, 0)
	}
	b.storage[to] = append(b.storage[to], record)
	return nil
}

func (b *InMemoryBanHistory) AddUnbanned(from User, to User, reason string) error {
	record := BanRecord{
		Time:   time.Now(),
		From:   from,
		To:     to,
		Action: "unban",
		Reason: reason,
	}
	if b.storage[to] == nil {
		b.storage[to] = make([]BanRecord, 0)
	}
	b.storage[to] = append(b.storage[to], record)
	return nil
}

func (b *InMemoryBanHistory) GetUserBanHistory(user User) ([]BanRecord, error) {
	return b.storage[user], nil
}
