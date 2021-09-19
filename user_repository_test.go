package main

import "testing"

func TestInMemoryStorage(t *testing.T) {
	t.Run("storage is created", func(t *testing.T) {
		storage := NewInMemoryStorage()

		if storage.storage == nil {
			t.Errorf("storage is nil")
		}
	})

	t.Run("can add key", func(t *testing.T) {
		storage := NewInMemoryStorage()

		user := User{
			Email:          "example",
			PasswordDigest: "example",
			FavoriteCake:   "example",
		}

		err := storage.Add(user.Email, user)
		if err != nil {
			t.Errorf(err.Error())
		}

		_, ok := storage.storage[user.Email]
		if !ok {
			t.Errorf("user is not stored in storage")
		}
	})

	t.Run("delete key", func(t *testing.T) {
		storage := NewInMemoryStorage()

		user := User{
			Email:          "example",
			PasswordDigest: "example",
			FavoriteCake:   "example",
		}

		err := storage.Add(user.Email, user)
		if err != nil {
			t.Errorf(err.Error())
		}

		u, err := storage.Delete(user.Email)
		if err != nil {
			t.Errorf(err.Error())
		}
		if u.Email != user.Email {
			t.Errorf("deleted user email does not match")
		}
	})
	t.Run("update key", func(t *testing.T) {
		storage := NewInMemoryStorage()

		user := User{
			Email:          "example",
			PasswordDigest: "example",
			FavoriteCake:   "example",
		}

		err := storage.Add(user.Email, user)
		if err != nil {
			t.Errorf(err.Error())
		}

		updatedUser := User{
			Email:          "example",
			PasswordDigest: "example",
			FavoriteCake:   "cake",
		}

		err = storage.Update(user.Email, updatedUser)
		if err != nil {
			t.Errorf(err.Error())
		}

		u, err := storage.Get(user.Email)
		if err != nil {
			t.Errorf(err.Error())
		}

		if u.FavoriteCake != updatedUser.FavoriteCake {
			t.Errorf("info is not updated")
		}

	})
	t.Run("delete key", func(t *testing.T) {
		storage := NewInMemoryStorage()

		user := User{
			Email:          "example",
			PasswordDigest: "example",
			FavoriteCake:   "example",
		}

		err := storage.Add(user.Email, user)
		if err != nil {
			t.Errorf(err.Error())
		}

		u, err := storage.Delete(user.Email)
		if err != nil {
			t.Errorf(err.Error())
		}
		_, ok := storage.storage[user.Email]
		if ok {
			t.Errorf("user is not deleted")
		}
		if u.Email != user.Email {
			t.Errorf("deleted data do not match")
		}
	})
}
