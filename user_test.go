package main

import (
	"bytes"
	"crypto/md5"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"
)

type parsedResponse struct {
	status int
	body   []byte
}

func createRequester(t *testing.T) func(req *http.Request, err error) parsedResponse {
	return func(req *http.Request, err error) parsedResponse {
		if err != nil {
			t.Errorf("unexpected error: %v", err)
			return parsedResponse{}
		}

		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
			return parsedResponse{}
		}

		resp, err := io.ReadAll(res.Body)
		res.Body.Close()

		if err != nil {
			t.Errorf("unexpected error: %v", err)
			return parsedResponse{}
		}

		return parsedResponse{res.StatusCode, resp}
	}
}

func prepareParams(t *testing.T, params map[string]interface{}) io.Reader {
	body, err := json.Marshal(params)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	return bytes.NewBuffer(body)
}

func newTestUserService() *UserService {
	return &UserService{
		Repository: NewInMemoryStorage(),
	}
}

func assertStatus(t *testing.T, expected int, r parsedResponse) {
	if r.status != expected {
		t.Errorf("Unexpected response status. Expected: %d, actual: %d", expected, r.status)
	}
}

func assertBody(t *testing.T, expected string, r parsedResponse) {
	actual := string(r.body)
	if actual != expected {
		t.Errorf("Unexpected response body. Expected: %s, actual: %s", expected, actual)
	}
}

func assertBodyRegex(t *testing.T, rx string, r parsedResponse) {
	rex, err := regexp.Compile(rx)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if !rex.Match(r.body) {
		t.Errorf("Unexpected response body. Expected regexp: %s, actual: %s", rx, string(r.body))
	}
}

func TestUsers_JWT(t *testing.T) {
	doRequest := createRequester(t)

	t.Run("user does not exist", func(t *testing.T) {
		u := newTestUserService()
		j, err := NewJWTService("public.rsa", "privkey.rsa")
		if err != nil {
			t.FailNow()
		}

		ts := httptest.NewServer(http.HandlerFunc(wrapJwt(j, u.JWT)))
		defer ts.Close()

		params := map[string]interface{}{
			"email":    "test@mail.com",
			"password": "12345678",
		}

		resp := doRequest(http.NewRequest(http.MethodPost, ts.URL, prepareParams(t, params)))
		assertStatus(t, 422, resp)
		assertBody(t, "no such user", resp)
	})

	t.Run("wrong password", func(t *testing.T) {
		u := newTestUserService()
		j, err := NewJWTService("public.rsa", "privkey.rsa")
		if err != nil {
			t.FailNow()
		}

		userParams := UserRegisterParams{
			Email:        "example@gmail.com",
			Password:     "right-password",
			FavoriteCake: "cheesecake",
		}

		passwordDigest := md5.New().Sum([]byte(userParams.Password))
		u.Repository.Add(userParams.Email, User{
			Email:          userParams.Email,
			PasswordDigest: string(passwordDigest),
			FavoriteCake:   userParams.FavoriteCake,
		})

		ts := httptest.NewServer(http.HandlerFunc(wrapJwt(j, u.JWT)))
		defer ts.Close()

		params := map[string]interface{}{
			"email":    userParams.Email,
			"password": userParams.Password + "wrong-part",
		}

		resp := doRequest(http.NewRequest(http.MethodPost, ts.URL, prepareParams(t, params)))
		assertStatus(t, 422, resp)
		assertBody(t, "invalid login params", resp)

	})

	t.Run("user token exists", func(t *testing.T) {
		u := newTestUserService()
		j, err := NewJWTService("public.rsa", "privkey.rsa")
		if err != nil {
			t.FailNow()
		}

		userParams := UserRegisterParams{
			Email:        "example@gmail.com",
			Password:     "right-password",
			FavoriteCake: "cheesecake",
		}

		passwordDigest := md5.New().Sum([]byte(userParams.Password))
		u.Repository.Add(userParams.Email, User{
			Email:          userParams.Email,
			PasswordDigest: string(passwordDigest),
			FavoriteCake:   userParams.FavoriteCake,
		})

		ts := httptest.NewServer(http.HandlerFunc(wrapJwt(j, u.JWT)))
		defer ts.Close()

		params := map[string]interface{}{
			"email":    userParams.Email,
			"password": userParams.Password,
		}

		resp := doRequest(http.NewRequest(http.MethodPost, ts.URL, prepareParams(t, params)))
		assertStatus(t, 200, resp)
		assertBodyRegex(t, "^[A-Za-z0-9-_=]+\\.[A-Za-z0-9-_=]+\\.?[A-Za-z0-9-_.+/=]*$", resp)
	})
}

func TestUsers_JWTAuth(t *testing.T) {
	doRequest := createRequester(t)

	t.Run("user unauthorized", func(t *testing.T) {
		u := newTestUserService()
		j, err := NewJWTService("public.rsa", "privkey.rsa")
		if err != nil {
			t.FailNow()
		}

		userParams := UserRegisterParams{
			Email:        "example@gmail.com",
			Password:     "right-password",
			FavoriteCake: "cheesecake",
		}

		passwordDigest := md5.New().Sum([]byte(userParams.Password))
		user := User{
			Email:          userParams.Email,
			PasswordDigest: string(passwordDigest),
			FavoriteCake:   userParams.FavoriteCake,
		}
		err = u.Repository.Add(userParams.Email, user)
		if err != nil {
			t.Errorf(err.Error())
		}

		_, err = j.GenerateJwt(user)
		if err != nil {
			t.Errorf(err.Error())
		}

		ts := httptest.NewServer(http.HandlerFunc(j.jwtAuth(u.Repository, GetCakeHandler)))
		defer ts.Close()

		params := map[string]interface{}{}

		request, err := http.NewRequest(http.MethodGet, ts.URL, prepareParams(t, params))
		resp := doRequest(request, err)
		assertStatus(t, 401, resp)
		assertBodyRegex(t, "unauthorized", resp)
	})

	t.Run("user authorized", func(t *testing.T) {
		u := newTestUserService()
		j, err := NewJWTService("public.rsa", "privkey.rsa")
		if err != nil {
			t.FailNow()
		}

		userParams := UserRegisterParams{
			Email:        "example@gmail.com",
			Password:     "right-password",
			FavoriteCake: "cheesecake",
		}

		passwordDigest := md5.New().Sum([]byte(userParams.Password))
		user := User{
			Email:          userParams.Email,
			PasswordDigest: string(passwordDigest),
			FavoriteCake:   userParams.FavoriteCake,
		}
		err = u.Repository.Add(userParams.Email, user)
		if err != nil {
			t.Errorf(err.Error())
		}

		jwt, err := j.GenerateJwt(user)
		if err != nil {
			t.Errorf(err.Error())
		}

		ts := httptest.NewServer(http.HandlerFunc(j.jwtAuth(u.Repository, GetCakeHandler)))
		defer ts.Close()

		params := map[string]interface{}{}

		request, err := http.NewRequest(http.MethodGet, ts.URL, prepareParams(t, params))
		request.Header.Set("Authorization", "Bearer "+jwt)
		resp := doRequest(request, err)
		assertStatus(t, 200, resp)
	})
}

func TestCake(t *testing.T) {
	doRequest := createRequester(t)

	t.Run("cake is given", func(t *testing.T) {
		u := newTestUserService()
		j, err := NewJWTService("public.rsa", "privkey.rsa")
		if err != nil {
			t.FailNow()
		}

		userParams := UserRegisterParams{
			Email:        "example@gmail.com",
			Password:     "right-password",
			FavoriteCake: "cheesecake",
		}

		passwordDigest := md5.New().Sum([]byte(userParams.Password))
		user := User{
			Email:          userParams.Email,
			PasswordDigest: string(passwordDigest),
			FavoriteCake:   userParams.FavoriteCake,
		}
		err = u.Repository.Add(userParams.Email, user)
		if err != nil {
			t.Errorf(err.Error())
		}

		jwt, err := j.GenerateJwt(user)
		if err != nil {
			t.Errorf(err.Error())
		}

		ts := httptest.NewServer(http.HandlerFunc(j.jwtAuth(u.Repository, GetCakeHandler)))
		defer ts.Close()

		params := map[string]interface{}{}

		request, err := http.NewRequest(http.MethodGet, ts.URL, prepareParams(t, params))
		request.Header.Set("Authorization", "Bearer "+jwt)
		resp := doRequest(request, err)
		assertStatus(t, 200, resp)
		assertBodyRegex(t, user.FavoriteCake, resp)
	})
}

func TestRegister(t *testing.T) {
	doRequest := createRequester(t)

	t.Run("wrong email", func(t *testing.T) {
		u := newTestUserService()

		ts := httptest.NewServer(http.HandlerFunc(u.Register))
		defer ts.Close()

		params := map[string]interface{}{
			"email":         "wrong email",
			"password":      "12345678",
			"favorite_cake": "cheesecake",
		}

		request, err := http.NewRequest(http.MethodPost, ts.URL, prepareParams(t, params))
		resp := doRequest(request, err)
		assertStatus(t, 422, resp)
		assertBodyRegex(t, "email not valid", resp)
	})
	t.Run("not secure password", func(t *testing.T) {
		u := newTestUserService()

		ts := httptest.NewServer(http.HandlerFunc(u.Register))
		defer ts.Close()

		params := map[string]interface{}{
			"email":         "ecample@gmail.com",
			"password":      "1234",
			"favorite_cake": "cheesecake",
		}

		request, err := http.NewRequest(http.MethodPost, ts.URL, prepareParams(t, params))
		resp := doRequest(request, err)
		assertStatus(t, 422, resp)
		assertBodyRegex(t, "password length is less than 8", resp)
	})
	t.Run("no cake", func(t *testing.T) {
		u := newTestUserService()

		ts := httptest.NewServer(http.HandlerFunc(u.Register))
		defer ts.Close()

		params := map[string]interface{}{
			"email":         "wxample@gmail.com",
			"password":      "12345678",
			"favorite_cake": "",
		}

		request, err := http.NewRequest(http.MethodPost, ts.URL, prepareParams(t, params))
		resp := doRequest(request, err)
		assertStatus(t, 422, resp)
		assertBodyRegex(t, "favorite cake is empty", resp)
	})
	t.Run("wrong cake", func(t *testing.T) {
		u := newTestUserService()

		ts := httptest.NewServer(http.HandlerFunc(u.Register))
		defer ts.Close()

		params := map[string]interface{}{
			"email":         "example@gmail.com",
			"password":      "12345678",
			"favorite_cake": "cheesecake8884",
		}

		request, err := http.NewRequest(http.MethodPost, ts.URL, prepareParams(t, params))
		resp := doRequest(request, err)
		assertStatus(t, 422, resp)
		assertBodyRegex(t, "favorite cake can only be alphabetic", resp)
	})

	t.Run("creates password digest", func(t *testing.T) {
		u := newTestUserService()

		ts := httptest.NewServer(http.HandlerFunc(u.Register))
		defer ts.Close()

		params := map[string]interface{}{
			"email":         "example@gmail.com",
			"password":      "12345678",
			"favorite_cake": "cheesecake",
		}

		request, err := http.NewRequest(http.MethodPost, ts.URL, prepareParams(t, params))
		resp := doRequest(request, err)
		assertStatus(t, 201, resp)
		user, err := u.Repository.Get(params["email"].(string))
		if err != nil {
			t.Errorf(err.Error())
		}

		if user.PasswordDigest == params["password"] {
			t.Errorf("password is not hashed")
		}
	})
}

func TestUserUpdateCake(t *testing.T) {
	doRequest := createRequester(t)

	t.Run("updates cake", func(t *testing.T) {
		u := newTestUserService()
		j, err := NewJWTService("public.rsa", "privkey.rsa")
		if err != nil {
			t.FailNow()
		}

		userParams := UserRegisterParams{
			Email:        "example@gmail.com",
			Password:     "right-password",
			FavoriteCake: "cheesecake",
		}

		passwordDigest := md5.New().Sum([]byte(userParams.Password))
		user := User{
			Email:          userParams.Email,
			PasswordDigest: string(passwordDigest),
			FavoriteCake:   userParams.FavoriteCake,
		}
		err = u.Repository.Add(userParams.Email, user)
		if err != nil {
			t.Errorf(err.Error())
		}

		jwt, err := j.GenerateJwt(user)
		if err != nil {
			t.Errorf(err.Error())
		}

		ts := httptest.NewServer(http.HandlerFunc(j.jwtAuth(u.Repository, u.UpdateCake)))
		defer ts.Close()

		params := map[string]interface{}{
			"favorite_cake": "burger",
		}

		request, err := http.NewRequest(http.MethodGet, ts.URL, prepareParams(t, params))
		request.Header.Set("Authorization", "Bearer "+jwt)
		resp := doRequest(request, err)
		assertStatus(t, 200, resp)
		assertBody(t, "updated", resp)

		usr, err := u.Repository.Get(userParams.Email)
		if err != nil {
			t.Errorf(err.Error())
		}
		if params["favorite_cake"] != usr.FavoriteCake {
			t.Errorf("updated info do not match")
		}
	})
}

func TestUserUpdateEmail(t *testing.T) {
	doRequest := createRequester(t)

	t.Run("updates cake", func(t *testing.T) {
		u := newTestUserService()
		j, err := NewJWTService("public.rsa", "privkey.rsa")
		if err != nil {
			t.FailNow()
		}

		userParams := UserRegisterParams{
			Email:        "example@gmail.com",
			Password:     "right-password",
			FavoriteCake: "cheesecake",
		}

		passwordDigest := md5.New().Sum([]byte(userParams.Password))
		user := User{
			Email:          userParams.Email,
			PasswordDigest: string(passwordDigest),
			FavoriteCake:   userParams.FavoriteCake,
		}
		err = u.Repository.Add(userParams.Email, user)
		if err != nil {
			t.Errorf(err.Error())
		}

		jwt, err := j.GenerateJwt(user)
		if err != nil {
			t.Errorf(err.Error())
		}

		ts := httptest.NewServer(http.HandlerFunc(j.jwtAuth(u.Repository, u.UpdateEmail)))
		defer ts.Close()

		params := map[string]interface{}{
			"email": "burger@gmail.com",
		}

		request, err := http.NewRequest(http.MethodPut, ts.URL, prepareParams(t, params))
		request.Header.Set("Authorization", "Bearer "+jwt)
		resp := doRequest(request, err)
		assertStatus(t, 200, resp)
		assertBody(t, "updated", resp)

		_, err = u.Repository.Get(params["email"].(string))
		if err != nil {
			t.Errorf(err.Error())
		}
	})
}

func TestUserUpdatePassword(t *testing.T) {
	doRequest := createRequester(t)

	t.Run("updates password", func(t *testing.T) {
		u := newTestUserService()
		j, err := NewJWTService("public.rsa", "privkey.rsa")
		if err != nil {
			t.FailNow()
		}

		userParams := UserRegisterParams{
			Email:        "example@gmail.com",
			Password:     "first-password",
			FavoriteCake: "cheesecake",
		}

		firstPasswordDigest := md5.New().Sum([]byte(userParams.Password))
		user := User{
			Email:          userParams.Email,
			PasswordDigest: string(firstPasswordDigest),
			FavoriteCake:   userParams.FavoriteCake,
		}
		err = u.Repository.Add(userParams.Email, user)
		if err != nil {
			t.Errorf(err.Error())
		}

		jwt, err := j.GenerateJwt(user)
		if err != nil {
			t.Errorf(err.Error())
		}

		ts := httptest.NewServer(http.HandlerFunc(j.jwtAuth(u.Repository, u.UpdatePassword)))
		defer ts.Close()

		params := map[string]interface{}{
			"password": "second-password",
		}

		request, err := http.NewRequest(http.MethodPut, ts.URL, prepareParams(t, params))
		request.Header.Set("Authorization", "Bearer "+jwt)
		resp := doRequest(request, err)
		assertStatus(t, 200, resp)
		assertBody(t, "updated", resp)

		usr, err := u.Repository.Get(userParams.Email)
		if err != nil {
			t.Errorf(err.Error())
		}

		newPasswordDigest := md5.New().Sum([]byte(params["password"].(string)))
		if usr.PasswordDigest != string(newPasswordDigest) {
			t.Errorf("password digest is not updated")
		}
	})
}

func TestUserGetMe(t *testing.T) {
	doRequest := createRequester(t)

	t.Run("", func(t *testing.T) {
		u := newTestUserService()
		j, err := NewJWTService("public.rsa", "privkey.rsa")
		if err != nil {
			t.FailNow()
		}

		userParams := UserRegisterParams{
			Email:        "example@gmail.com",
			Password:     "first-password",
			FavoriteCake: "cheesecake",
		}

		passwordDigest := md5.New().Sum([]byte(userParams.Password))
		user := User{
			Email:          userParams.Email,
			PasswordDigest: string(passwordDigest),
			FavoriteCake:   userParams.FavoriteCake,
		}
		err = u.Repository.Add(userParams.Email, user)
		if err != nil {
			t.Errorf(err.Error())
		}

		jwt, err := j.GenerateJwt(user)
		if err != nil {
			t.Errorf(err.Error())
		}

		ut, err := u.Repository.Get(user.Email)
		procError(t, err)

		ut.PasswordDigest = ""
		out, err := json.Marshal(ut)
		procError(t, err)

		ts := httptest.NewServer(http.HandlerFunc(j.jwtAuth(u.Repository, u.GetMe)))
		defer ts.Close()

		params := map[string]interface{}{}

		request, err := http.NewRequest(http.MethodPut, ts.URL, prepareParams(t, params))
		request.Header.Set("Authorization", "Bearer "+jwt)
		resp := doRequest(request, err)
		assertStatus(t, 200, resp)
		assertBody(t, string(out), resp)
	})
}
