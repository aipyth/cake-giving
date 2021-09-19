package main

import (
	"crypto/md5"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/openware/rango/pkg/auth"
)

type JWTService struct {
	keys *auth.KeyStore
}

type ProtectedHandler func(rw http.ResponseWriter, r *http.Request, u User)

func NewJWTService(privKeyPath, pubKeyPath string) (*JWTService, error) {
	keys, err := auth.LoadOrGenerateKeys(privKeyPath, pubKeyPath)
	if err != nil {
		return nil, err
	}
	return &JWTService{keys: keys}, nil
}

func (j *JWTService) ParseJWT(jwt string) (auth.Auth, error) {
	return auth.ParseAndValidate(jwt, j.keys.PublicKey)
}

func (j *JWTService) GenerateJwt(u User) (string, error) {
	return auth.ForgeToken("empty", u.Email, "empty", 0, j.keys.PrivateKey, nil)
}

type JWTParams struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func (u *UserService) JWT(w http.ResponseWriter, r *http.Request, jwtService *JWTService) {
	params := &JWTParams{}
	err := json.NewDecoder(r.Body).Decode(params)
	if err != nil {
		handleError(errors.New("could not read params"), w)
		return
	}

	passwordDigest := md5.New().Sum([]byte(params.Password))
	user, err := u.Repository.Get(params.Email)
	if err != nil {
		handleError(err, w)
		return
	}

	if string(passwordDigest) != user.PasswordDigest {
		handleError(errors.New("invalid login params"), w)
		return
	}

	token, err := jwtService.GenerateJwt(user)
	if err != nil {
		handleError(err, w)
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(token))
}

func (j *JWTService) jwtAuth(
	users UserRepository,
	h ProtectedHandler,
) http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		token := strings.TrimPrefix(authHeader, "Bearer ")
		auth, err := j.ParseJWT(token)
		if err != nil {
			rw.WriteHeader(http.StatusUnauthorized)
			rw.Write([]byte("unauthorized"))
			return
		}

		user, err := users.Get(auth.Email)
		if err != nil {
			rw.WriteHeader(http.StatusUnauthorized)
			rw.Write([]byte("unauthorized"))
			return
		}

		if user.Banned {
			rw.WriteHeader(401)
			rw.Write([]byte(user.BanReason))
		}

		h(rw, r, user)
	}
}

func (j *JWTService) jwtAdminAuth(
	users UserRepository,
	h ProtectedHandler,
) http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		token := strings.TrimPrefix(authHeader, "Bearer ")
		auth, err := j.ParseJWT(token)
		if err != nil {
			rw.WriteHeader(http.StatusUnauthorized)
			rw.Write([]byte("unauthorized"))
			return
		}

		user, err := users.Get(auth.Email)
		if err != nil {
			rw.WriteHeader(http.StatusUnauthorized)
			rw.Write([]byte("unauthorized"))
			return
		}

		if user.Banned {
			rw.WriteHeader(401)
			rw.Write([]byte(user.BanReason))
			return
		}

		if !user.IsAdmin() {
			rw.WriteHeader(401)
			rw.Write([]byte("user cannot access admin api"))
			return
		}

		h(rw, r, user)
	}
}

func (j *JWTService) jwtSuperadminAuth(
	users UserRepository,
	h ProtectedHandler,
) http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		token := strings.TrimPrefix(authHeader, "Bearer ")
		auth, err := j.ParseJWT(token)
		if err != nil {
			rw.WriteHeader(http.StatusUnauthorized)
			rw.Write([]byte("unauthorized"))
			return
		}

		user, err := users.Get(auth.Email)
		if err != nil {
			rw.WriteHeader(http.StatusUnauthorized)
			rw.Write([]byte("unauthorized"))
			return
		}

		if user.Banned {
			rw.WriteHeader(401)
			rw.Write([]byte(user.BanReason))
			return
		}

		if user.Role != "superadmin" {
			rw.WriteHeader(401)
			rw.Write([]byte("access denied"))
			return
		}

		h(rw, r, user)
	}
}
