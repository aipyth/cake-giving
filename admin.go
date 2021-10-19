package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
)

type AdminService struct {
    Hub *Hub
	Repository UserRepository
	BanHistory BanHistoryRepository
    Publisher *Publisher
}

type BanParams struct {
	Email  string `json:"email"`
	Reason string `json:"reason"`
}

type UnbanParams struct {
	Email  string `json:"email"`
	Reason string `json:"reason"`
}

type PromoteToAdminParams struct {
	Email string `json:"email"`
}

type FireAdminParams struct {
	Email string `json:"email"`
}

func (a *AdminService) BanUser(w http.ResponseWriter, r *http.Request, user User) {
	var params BanParams
	err := json.NewDecoder(r.Body).Decode(&params)
	if err != nil {
		handleError(errors.New("could not parse params"), w)
		return
	}

	if err := validateEmail(params.Email); err != nil {
		handleError(err, w)
		return
	}
	if params.Reason == "" {
		handleError(errors.New("reason to ban is not specified or empty"), w)
		return
	}

	userToBan, err := a.Repository.Get(params.Email)
	if err != nil {
		handleError(err, w)
		return
	}

	if user.Role == userToBan.Role || userToBan.Role == "superadmin" {
		handleError(errors.New("no such permission to ban this user"), w)
		return
	}

	userToBan.Banned = true
	userToBan.BanReason = params.Reason
	err = a.Repository.Update(userToBan.Email, userToBan)
	if err != nil {
		handleError(err, w)
		return
	}

	err = a.BanHistory.AddBanned(user, userToBan, params.Reason)
	if err != nil {
		handleError(err, w)
		return
	}
    
    a.Publisher.Publish(fmt.Sprintf("user %s is being banned", user.Email))

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("banned"))
}

func (a *AdminService) UnbanUser(w http.ResponseWriter, r *http.Request, user User) {
	var params UnbanParams
	err := json.NewDecoder(r.Body).Decode(&params)
	if err != nil {
		handleError(errors.New("could not parse params"), w)
		return
	}

	if err := validateEmail(params.Email); err != nil {
		handleError(err, w)
		return
	}
	if params.Reason == "" {
		handleError(errors.New("reason to unban is not specified or empty"), w)
		return
	}

	userToUnban, err := a.Repository.Get(params.Email)
	if err != nil {
		handleError(err, w)
		return
	}

	if user.Role == userToUnban.Role {
		handleError(errors.New("no such permission to unban this user"), w)
		return
	}

	userToUnban.Banned = false
	userToUnban.BanReason = ""
	err = a.Repository.Update(userToUnban.Email, userToUnban)
	if err != nil {
		handleError(err, w)
		return
	}

	err = a.BanHistory.AddUnbanned(user, userToUnban, params.Reason)
	if err != nil {
		handleError(err, w)
		return
	}

    a.Publisher.Publish(fmt.Sprintf("user %s is being unbanned", user.Email))

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("unbanned"))
}

func (a *AdminService) InspectUserBanHistory(w http.ResponseWriter, r *http.Request, user User) {
	email := r.URL.Query().Get("email")
	if err := validateEmail(email); err != nil {
		handleError(err, w)
		return
	}

	userToInspect, err := a.Repository.Get(email)
	if err != nil {
		handleError(err, w)
		return
	}

	hist, err := a.BanHistory.GetUserBanHistory(userToInspect)
	if err != nil {
		handleError(err, w)
		return
	}
	out, err := json.Marshal(hist)
	if err != nil {
		handleError(errors.New("error serializing user ban history"), w)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(out)
}

func (a *AdminService) PromoteToAdmin(w http.ResponseWriter, r *http.Request, user User) {
	var params PromoteToAdminParams
	err := json.NewDecoder(r.Body).Decode(&params)
	if err != nil {
		handleError(errors.New("could not parse params"), w)
		return
	}

	if err := validateEmail(params.Email); err != nil {
		handleError(err, w)
		return
	}

	userToPromote, err := a.Repository.Get(params.Email)
	if err != nil {
		handleError(err, w)
		return
	}

	if userToPromote.Role != "user" {
		handleError(errors.New("cannot promote this user"), w)
		return
	}

	userToPromote.Role = "admin"
	err = a.Repository.Update(userToPromote.Email, userToPromote)
	if err != nil {
		handleError(err, w)
		return
	}

    a.Publisher.Publish(fmt.Sprintf("user %s is being promoted to admin", user.Email))

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("promoted"))
}

func (a *AdminService) FireAdmin(w http.ResponseWriter, r *http.Request, user User) {
	var params FireAdminParams
	err := json.NewDecoder(r.Body).Decode(&params)
	if err != nil {
		handleError(errors.New("could not parse params"), w)
		return
	}

	if err := validateEmail(params.Email); err != nil {
		handleError(err, w)
		return
	}

	userToFire, err := a.Repository.Get(params.Email)
	if err != nil {
		handleError(err, w)
		return
	}

	if userToFire.Role != "admin" {
		handleError(errors.New("cannot fire this user"), w)
		return
	}

	userToFire.Role = "user"
	err = a.Repository.Update(userToFire.Email, userToFire)
	if err != nil {
		handleError(err, w)
		return
	}

    a.Publisher.Publish(fmt.Sprintf("user %s is being fired out of admins", user.Email))

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("fired"))
}
