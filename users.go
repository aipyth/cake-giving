package main

import (
	"crypto/md5"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var ( 
    registeredUsers = promauto.NewCounter(prometheus.CounterOpts{
        Name: "registered_users",
        Help: "The total number of registeres users.",
    })
    cakesUpdated = promauto.NewCounter(prometheus.CounterOpts{
        Name: "cakes_updated",
        Help: "The total number of cakes updates.",
    })
)

type User struct {
	Email          string
	PasswordDigest string
	Role           string
	FavoriteCake   string
	Banned         bool
	BanReason      string
}

type UserRepository interface {
	Add(string, User) error
	Get(string) (User, error)
	Update(string, User) error
	Delete(string) (User, error)
}

type UserService struct {
	Repository UserRepository
    Publisher *Publisher
}

type UserRegisterParams struct {
	Email        string `json:"email"`
	Password     string `json:"password"`
	FavoriteCake string `json:"favorite_cake"`
}

type UserUpdateCakeParams struct {
	FavoriteCake string `json:"favorite_cake"`
}

type UserUpdateEmailParams struct {
	Email string `json:"email"`
}

type UserUpdatePasswordParams struct {
	Password string `json:"password"`
}

func validateCake(cake string) error {
	// 3. Favorite cake not empty
	if cake == "" {
		return errors.New("favorite cake is empty")
	}
	// 4. Favorite cake only alphabetic
	cakeRegex := regexp.MustCompile("^[a-zA-Z ]+$")
	if !cakeRegex.Match([]byte(cake)) {
		return errors.New("favorite cake can only be alphabetic")
	}

	return nil
}

func validateEmail(email string) error {
	// 1. Email is valid
	emailRegex := regexp.MustCompile("^[\\w-\\.]+@([\\w-]+\\.)+[\\w-]{2,4}$")
	if !emailRegex.Match([]byte(email)) {
		return errors.New("email not valid")
	}
	return nil
}

func validatePassword(password string) error {
	// 2. Password at least 8 symbols
	if len(password) < 8 {
		return errors.New("password length is less than 8")
	}
	return nil
}

func validateRegisterParams(p *UserRegisterParams) error {
	if err := validateEmail(p.Email); err != nil {
		return err
	}
	if err := validatePassword(p.Password); err != nil {
		return err
	}
	if err := validateCake(p.FavoriteCake); err != nil {
		return err
	}

	return nil
}

func (u *User) IsAdmin() bool {
	return u.Role == "admin" || u.Role == "superadmin"
}

func (u *UserService) Register(w http.ResponseWriter, r *http.Request) {
	params := &UserRegisterParams{}
	err := json.NewDecoder(r.Body).Decode(params)
	if err != nil {
		handleError(errors.New("could not read prarms"), w)
		return
	}

	if err := validateRegisterParams(params); err != nil {
		handleError(err, w)
		return
	}

	passwordDigest := md5.New().Sum([]byte(params.Password))
	newUser := User{
		Email:          params.Email,
		PasswordDigest: string(passwordDigest),
		FavoriteCake:   params.FavoriteCake,
		Role:           "user",
	}

	err = u.Repository.Add(params.Email, newUser)
	if err != nil {
		handleError(err, w)
		return
	}

    u.Publisher.Publish(fmt.Sprintf("user %s has been registered", newUser.Email))

    registeredUsers.Inc()

	w.WriteHeader(http.StatusCreated)
	w.Write([]byte("registered"))
}

func (us *UserService) UpdateCake(w http.ResponseWriter, r *http.Request, user User) {
	params := &UserUpdateCakeParams{}
	err := json.NewDecoder(r.Body).Decode(params)
	if err != nil {
		handleError(errors.New("could not read params"), w)
		return
	}

	err = validateCake(params.FavoriteCake)
	if err != nil {
		handleError(err, w)
		return
	}

	user.FavoriteCake = params.FavoriteCake
	err = us.Repository.Update(user.Email, user)
	if err != nil {
		handleError(err, w)
		return
	}

    us.Publisher.Publish(fmt.Sprintf("user %s has updated his cake", user.Email))

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("updated"))
}

func (u *UserService) UpdateEmail(w http.ResponseWriter, r *http.Request, user User) {
	params := &UserUpdateEmailParams{}
	err := json.NewDecoder(r.Body).Decode(params)
	if err != nil {
		handleError(errors.New("could not read params"), w)
		return
	}

	err = validateEmail(params.Email)
	if err != nil {
		handleError(err, w)
		return
	}

	_, err = u.Repository.Delete(user.Email)
	if err != nil {
		handleError(err, w)
		return
	}
	user.Email = params.Email
	err = u.Repository.Add(user.Email, user)
	if err != nil {
		handleError(err, w)
		return
	}

    u.Publisher.Publish(fmt.Sprintf("user %s has updated his email", user.Email))

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("updated"))
}

func (u *UserService) UpdatePassword(w http.ResponseWriter, r *http.Request, user User) {
	params := &UserUpdatePasswordParams{}
	err := json.NewDecoder(r.Body).Decode(params)
	if err != nil {
		handleError(errors.New("could not read prarms"), w)
		return
	}

	if err := validatePassword(params.Password); err != nil {
		handleError(err, w)
		return
	}

	passwordDigest := md5.New().Sum([]byte(params.Password))
	user.PasswordDigest = string(passwordDigest)

	err = u.Repository.Update(user.Email, user)
	if err != nil {
		handleError(err, w)
		return
	}

    u.Publisher.Publish(fmt.Sprintf("user %s has updated his password", user.Email))

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("updated"))
}

func (u *UserService) GetMe(w http.ResponseWriter, r *http.Request, user User) {
	user.PasswordDigest = ""
	out, err := json.Marshal(user)
	if err != nil {
		handleError(errors.New("could not encode response"), w)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(out)
}

func handleError(err error, w http.ResponseWriter) {
	w.WriteHeader(http.StatusUnprocessableEntity)
	w.Write([]byte(err.Error()))
}
