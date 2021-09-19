package main

import (
	"crypto/md5"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func procError(t *testing.T, err error) {
	if err != nil {
		t.Error(err)
	}
}

func InitUser(t *testing.T) (
	*UserService,
	*AdminService,
	*JWTService,
	*User,
	*User,
	string,
	string,
) {
	u := newTestUserService()
	adminService := AdminService{
		Repository: u.Repository,
		BanHistory: NewInMemoryBanHistory(),
	}
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
		Role:           "user",
	}
	err = u.Repository.Add(userParams.Email, user)
	if err != nil {
		t.Errorf(err.Error())
	}

	err = addSuperadmin(u.Repository)
	if err != nil {
		t.Error(err)
	}

	admin, err := u.Repository.Get(os.Getenv("CAKE_ADMIN_EMAIL"))
	if err != nil {
		t.Error(err)
	}

	jwta, err := j.GenerateJwt(admin)
	if err != nil {
		t.Errorf(err.Error())
	}
	jwtu, err := j.GenerateJwt(user)
	if err != nil {
		t.Errorf(err.Error())
	}

	return u, &adminService, j, &user, &admin, jwtu, jwta
}

func TestAdminApiAccess(t *testing.T) {
	doRequest := createRequester(t)

	t.Run("banned user cannot access admin api", func(t *testing.T) {
		u, adminService, j, user, _, jwt, _ := InitUser(t)

		user.Banned = true
		err := u.Repository.Update(user.Email, *user)
		procError(t, err)

		ts := httptest.NewServer(http.HandlerFunc(j.jwtAdminAuth(u.Repository, adminService.BanUser)))
		defer ts.Close()

		params := map[string]interface{}{}

		request, err := http.NewRequest(http.MethodPut, ts.URL, prepareParams(t, params))
		request.Header.Set("Authorization", "Bearer "+jwt)
		resp := doRequest(request, err)
		assertStatus(t, 401, resp)
	})

	t.Run("regular user cannot access admin api", func(t *testing.T) {
		u, adminService, j, _, _, jwt, _ := InitUser(t)

		ts := httptest.NewServer(http.HandlerFunc(j.jwtAdminAuth(u.Repository, adminService.BanUser)))
		defer ts.Close()

		params := map[string]interface{}{}

		request, err := http.NewRequest(http.MethodPut, ts.URL, prepareParams(t, params))
		request.Header.Set("Authorization", "Bearer "+jwt)
		resp := doRequest(request, err)
		assertStatus(t, 401, resp)
		assertBody(t, "user cannot access admin api", resp)
	})

	t.Run("regular user cannot access superadmin api", func(t *testing.T) {
		u, adminService, j, _, _, jwt, _ := InitUser(t)

		ts := httptest.NewServer(http.HandlerFunc(j.jwtSuperadminAuth(u.Repository, adminService.BanUser)))
		defer ts.Close()

		params := map[string]interface{}{}

		request, err := http.NewRequest(http.MethodPut, ts.URL, prepareParams(t, params))
		request.Header.Set("Authorization", "Bearer "+jwt)
		resp := doRequest(request, err)
		assertStatus(t, 401, resp)
		assertBody(t, "access denied", resp)
	})

	t.Run("admin can't access superadmin api", func(t *testing.T) {
		u, adminService, j, user, _, _, _ := InitUser(t)
		user.Role = "admin"
		err := u.Repository.Update(user.Email, *user)
		procError(t, err)

		jwt, err := j.GenerateJwt(*user)
		procError(t, err)

		ts := httptest.NewServer(http.HandlerFunc(j.jwtSuperadminAuth(u.Repository, adminService.BanUser)))
		defer ts.Close()

		params := map[string]interface{}{}

		request, err := http.NewRequest(http.MethodPut, ts.URL, prepareParams(t, params))
		request.Header.Set("Authorization", "Bearer "+jwt)
		resp := doRequest(request, err)
		assertStatus(t, 401, resp)
		assertBody(t, "access denied", resp)
	})

	t.Run("admin access admin api", func(t *testing.T) {
		u, adminService, j, user, _, _, _ := InitUser(t)
		user.Role = "admin"
		err := u.Repository.Update(user.Email, *user)
		procError(t, err)

		jwt, err := j.GenerateJwt(*user)
		procError(t, err)

		ts := httptest.NewServer(http.HandlerFunc(j.jwtAdminAuth(u.Repository, adminService.BanUser)))
		defer ts.Close()

		params := map[string]interface{}{}

		request, err := http.NewRequest(http.MethodPut, ts.URL, prepareParams(t, params))
		request.Header.Set("Authorization", "Bearer "+jwt)
		resp := doRequest(request, err)
		assertStatus(t, 422, resp)
	})

	t.Run("superadmin access superadmin api", func(t *testing.T) {
		u, adminService, j, _, _, _, jwt := InitUser(t)

		ts := httptest.NewServer(http.HandlerFunc(j.jwtAdminAuth(u.Repository, adminService.BanUser)))
		defer ts.Close()

		params := map[string]interface{}{}

		request, err := http.NewRequest(http.MethodPut, ts.URL, prepareParams(t, params))
		request.Header.Set("Authorization", "Bearer "+jwt)
		resp := doRequest(request, err)
		assertStatus(t, 422, resp)
	})
}

func TestAdminBan(t *testing.T) {
	doRequest := createRequester(t)

	t.Run("reason not spec or empty", func(t *testing.T) {
		u, adminService, j, user, _, _, jwt := InitUser(t)

		banReason := ""

		ts := httptest.NewServer(http.HandlerFunc(j.jwtAdminAuth(u.Repository, adminService.BanUser)))
		defer ts.Close()

		params := map[string]interface{}{
			"email":  user.Email,
			"reason": banReason,
		}

		request, err := http.NewRequest(http.MethodPut, ts.URL, prepareParams(t, params))
		request.Header.Set("Authorization", "Bearer "+jwt)

		resp := doRequest(request, err)
		assertStatus(t, 422, resp)
		assertBody(t, "reason to ban is not specified or empty", resp)

		bannedUser, err := u.Repository.Get(user.Email)
		if err != nil {
			t.Error(err)
			return
		}

		if bannedUser.Banned {
			t.Errorf("user is banned")
		}
	})

	t.Run("admin cannot ban superadmin", func(t *testing.T) {
		u, adminService, j, user, admin, jwt, _ := InitUser(t)

		user.Role = "admin"
		err := u.Repository.Update(user.Email, *user)
		procError(t, err)

		banReason := "test"

		ts := httptest.NewServer(http.HandlerFunc(j.jwtAdminAuth(u.Repository, adminService.BanUser)))
		defer ts.Close()

		params := map[string]interface{}{
			"email":  admin.Email,
			"reason": banReason,
		}

		request, err := http.NewRequest(http.MethodPut, ts.URL, prepareParams(t, params))
		request.Header.Set("Authorization", "Bearer "+jwt)

		resp := doRequest(request, err)
		assertStatus(t, 422, resp)
		assertBody(t, "no such permission to ban this user", resp)
	})

	t.Run("admin cannot ban admin", func(t *testing.T) {
		u, adminService, j, user, _, jwt, _ := InitUser(t)

		user.Role = "admin"
		err := u.Repository.Update(user.Email, *user)
		procError(t, err)

		userToBan := User{
			Email:          "exampm@mail.com",
			PasswordDigest: "",
			Role:           "admin",
		}
		err = u.Repository.Add(userToBan.Email, userToBan)
		procError(t, err)

		banReason := "test"

		ts := httptest.NewServer(http.HandlerFunc(j.jwtAdminAuth(u.Repository, adminService.BanUser)))
		defer ts.Close()

		params := map[string]interface{}{
			"email":  userToBan.Email,
			"reason": banReason,
		}

		request, err := http.NewRequest(http.MethodPut, ts.URL, prepareParams(t, params))
		request.Header.Set("Authorization", "Bearer "+jwt)

		resp := doRequest(request, err)
		assertStatus(t, 422, resp)
		assertBody(t, "no such permission to ban this user", resp)
	})

	t.Run("admin bans", func(t *testing.T) {
		u, adminService, j, user, admin, _, jwt := InitUser(t)

		banReason := "test"

		ts := httptest.NewServer(http.HandlerFunc(j.jwtAdminAuth(u.Repository, adminService.BanUser)))
		defer ts.Close()

		params := map[string]interface{}{
			"email":  user.Email,
			"reason": banReason,
		}

		request, err := http.NewRequest(http.MethodPut, ts.URL, prepareParams(t, params))
		request.Header.Set("Authorization", "Bearer "+jwt)

		resp := doRequest(request, err)
		assertStatus(t, 200, resp)
		assertBody(t, "banned", resp)

		bannedUser, err := u.Repository.Get(user.Email)
		if err != nil {
			t.Error(err)
			return
		}

		if !bannedUser.Banned {
			t.Errorf("user is not banned")
		}
		if bannedUser.BanReason != banReason {
			t.Errorf("ban reason is invalid")
		}

		h, err := adminService.BanHistory.GetUserBanHistory(bannedUser)
		if err != nil {
			t.Error(err)
		}

		if len(h) != 1 {
			t.Errorf("ban history length is not 1")
		}

		record := h[0]
		if record.From.Email != admin.Email {
			t.Error("ban comes not from admin")
		}
		if record.To != bannedUser {
			t.Error("ban comes not to user")
		}
		if record.Action != "ban" {
			t.Error("record is not of type `ban`")
		}
		if record.Reason != banReason {
			t.Error("ban reason is invalid in record")
		}
	})

	t.Run("invalid email", func(t *testing.T) {
		u, adminService, j, _, _, _, jwt := InitUser(t)

		ts := httptest.NewServer(http.HandlerFunc(j.jwtAdminAuth(u.Repository, adminService.BanUser)))
		defer ts.Close()

		params := map[string]interface{}{
			"email": "sad;las",
		}

		request, err := http.NewRequest(http.MethodPut, ts.URL, prepareParams(t, params))
		request.Header.Set("Authorization", "Bearer "+jwt)

		resp := doRequest(request, err)
		assertStatus(t, 422, resp)
		assertBody(t, "email not valid", resp)
	})
}

func TestAdminUnban(t *testing.T) {
	doRequest := createRequester(t)

	t.Run("reason not spec or empty", func(t *testing.T) {
		u, adminService, j, user, _, _, jwt := InitUser(t)

		banReason := ""

		ts := httptest.NewServer(http.HandlerFunc(j.jwtAdminAuth(u.Repository, adminService.UnbanUser)))
		defer ts.Close()

		params := map[string]interface{}{
			"email":  user.Email,
			"reason": banReason,
		}

		request, err := http.NewRequest(http.MethodPut, ts.URL, prepareParams(t, params))
		request.Header.Set("Authorization", "Bearer "+jwt)

		resp := doRequest(request, err)
		assertStatus(t, 422, resp)
		assertBody(t, "reason to unban is not specified or empty", resp)
	})

	t.Run("admin cannot unban admin", func(t *testing.T) {
		u, adminService, j, user, _, jwt, _ := InitUser(t)

		user.Role = "admin"
		err := u.Repository.Update(user.Email, *user)
		procError(t, err)

		userToUnban := User{
			Email:          "exampm@mail.com",
			PasswordDigest: "",
			Role:           "admin",
			Banned:         true,
		}
		err = u.Repository.Add(userToUnban.Email, userToUnban)
		procError(t, err)

		banReason := "test"

		ts := httptest.NewServer(http.HandlerFunc(j.jwtAdminAuth(u.Repository, adminService.UnbanUser)))
		defer ts.Close()

		params := map[string]interface{}{
			"email":  userToUnban.Email,
			"reason": banReason,
		}

		request, err := http.NewRequest(http.MethodPut, ts.URL, prepareParams(t, params))
		request.Header.Set("Authorization", "Bearer "+jwt)

		resp := doRequest(request, err)
		assertStatus(t, 422, resp)
		assertBody(t, "no such permission to unban this user", resp)
	})

	t.Run("admin unbans", func(t *testing.T) {
		u, adminService, j, user, admin, _, jwt := InitUser(t)

		unbanReason := "test"

		ts := httptest.NewServer(http.HandlerFunc(j.jwtAdminAuth(u.Repository, adminService.UnbanUser)))
		defer ts.Close()

		params := map[string]interface{}{
			"email":  user.Email,
			"reason": unbanReason,
		}

		request, err := http.NewRequest(http.MethodPut, ts.URL, prepareParams(t, params))
		request.Header.Set("Authorization", "Bearer "+jwt)

		resp := doRequest(request, err)
		assertStatus(t, 200, resp)
		assertBody(t, "unbanned", resp)

		unbannedUser, err := u.Repository.Get(user.Email)
		if err != nil {
			t.Error(err)
			return
		}

		if unbannedUser.Banned {
			t.Errorf("user is still banned")
		}
		if unbannedUser.BanReason != "" {
			t.Errorf("ban reason is invalid")
		}

		h, err := adminService.BanHistory.GetUserBanHistory(unbannedUser)
		if err != nil {
			t.Error(err)
		}

		if len(h) != 1 {
			t.Errorf("ban history length is not 1")
		}

		record := h[0]
		if record.From.Email != admin.Email {
			t.Error("unban comes not from admin")
		}
		if record.To.Email != unbannedUser.Email {
			t.Error("unban comes not to user")
		}
		if record.Action != "unban" {
			t.Error("record is not of type `unban`")
		}
		if record.Reason != unbanReason {
			t.Error("unban reason is invalid in record")
		}
	})

	t.Run("invalid email", func(t *testing.T) {
		u, adminService, j, _, _, _, jwt := InitUser(t)

		ts := httptest.NewServer(http.HandlerFunc(j.jwtAdminAuth(u.Repository, adminService.UnbanUser)))
		defer ts.Close()

		params := map[string]interface{}{
			"email": "sad;las",
		}

		request, err := http.NewRequest(http.MethodPut, ts.URL, prepareParams(t, params))
		request.Header.Set("Authorization", "Bearer "+jwt)

		resp := doRequest(request, err)
		assertStatus(t, 422, resp)
		assertBody(t, "email not valid", resp)
	})
}

func TestAdminInspects(t *testing.T) {
	doRequest := createRequester(t)

	t.Run("", func(t *testing.T) {
		u, adminService, j, user, admin, _, jwt := InitUser(t)

		adminService.BanHistory.AddBanned(*admin, *user, "test")

		ts := httptest.NewServer(http.HandlerFunc(j.jwtAdminAuth(u.Repository, adminService.InspectUserBanHistory)))
		defer ts.Close()

		params := map[string]interface{}{}

		request, err := http.NewRequest(http.MethodPut, ts.URL, prepareParams(t, params))
		request.Header.Set("Authorization", "Bearer "+jwt)

		q := request.URL.Query()
		q.Add("email", user.Email)
		request.URL.RawQuery = q.Encode()

		resp := doRequest(request, err)
		assertStatus(t, 200, resp)

		var uhhh []BanRecord
		err = json.Unmarshal(resp.body, &uhhh)
		if err != nil {
			t.Error(err)
			return
		}

		if len(uhhh) != 1 {
			t.Errorf("theres %d records instead of %d in response", len(uhhh), 1)
			return
		}

		record := uhhh[0]
		if record.Action != "ban" {
			t.Error("record action is invalid")
		}
		if record.From.Email != admin.Email {
			t.Error("ban comes not from admin")
		}
		if record.To.Email != user.Email {
			t.Error("invalid record of user banned")
		}
		if record.Reason != "test" {
			t.Error("reason is invalid")
		}
	})

	t.Run("invalid email", func(t *testing.T) {
		u, adminService, j, _, _, _, jwt := InitUser(t)

		ts := httptest.NewServer(http.HandlerFunc(j.jwtAdminAuth(u.Repository, adminService.InspectUserBanHistory)))
		defer ts.Close()

		params := map[string]interface{}{
			"email": "sad;las",
		}

		request, err := http.NewRequest(http.MethodPut, ts.URL, prepareParams(t, params))
		request.Header.Set("Authorization", "Bearer "+jwt)

		resp := doRequest(request, err)
		assertStatus(t, 422, resp)
		assertBody(t, "email not valid", resp)
	})
}

func TestAdminPromote(t *testing.T) {
	doRequest := createRequester(t)

	t.Run("admin promotes", func(t *testing.T) {
		u, adminService, j, user, _, _, jwt := InitUser(t)

		ts := httptest.NewServer(http.HandlerFunc(j.jwtSuperadminAuth(u.Repository, adminService.PromoteToAdmin)))
		defer ts.Close()

		params := map[string]interface{}{
			"email": user.Email,
		}

		request, err := http.NewRequest(http.MethodPut, ts.URL, prepareParams(t, params))
		request.Header.Set("Authorization", "Bearer "+jwt)

		resp := doRequest(request, err)
		assertStatus(t, 200, resp)
		assertBody(t, "promoted", resp)

		promoted, err := u.Repository.Get(user.Email)
		if err != nil {
			t.Error(err)
			return
		}
		if promoted.Role != "admin" {
			t.Errorf("promoted user is not admin")
		}
	})

	t.Run("admin cannot promote admin", func(t *testing.T) {
		u, adminService, j, user, _, jwt, _ := InitUser(t)

		user.Role = "admin"
		err := u.Repository.Update(user.Email, *user)
		procError(t, err)

		otherAdmin := User{
			Email:          "exampm@mail.com",
			PasswordDigest: "",
			Role:           "admin",
		}
		err = u.Repository.Add(otherAdmin.Email, otherAdmin)
		procError(t, err)

		ts := httptest.NewServer(http.HandlerFunc(j.jwtSuperadminAuth(u.Repository, adminService.PromoteToAdmin)))
		defer ts.Close()

		params := map[string]interface{}{
			"email": otherAdmin.Email,
		}

		request, err := http.NewRequest(http.MethodPut, ts.URL, prepareParams(t, params))
		request.Header.Set("Authorization", "Bearer "+jwt)

		resp := doRequest(request, err)
		assertStatus(t, 401, resp)
		assertBody(t, "access denied", resp)
	})

	t.Run("superadmin cannot promote admin", func(t *testing.T) {
		u, adminService, j, user, _, _, jwt := InitUser(t)

		user.Role = "admin"
		err := u.Repository.Update(user.Email, *user)
		procError(t, err)

		ts := httptest.NewServer(http.HandlerFunc(j.jwtSuperadminAuth(u.Repository, adminService.PromoteToAdmin)))
		defer ts.Close()

		params := map[string]interface{}{
			"email": user.Email,
		}

		request, err := http.NewRequest(http.MethodPut, ts.URL, prepareParams(t, params))
		request.Header.Set("Authorization", "Bearer "+jwt)

		resp := doRequest(request, err)
		assertStatus(t, 422, resp)
		assertBody(t, "cannot promote this user", resp)
	})

	t.Run("superadmin cannot promote superadmin", func(t *testing.T) {
		u, adminService, j, user, _, _, jwt := InitUser(t)

		user.Role = "superadmin"
		err := u.Repository.Update(user.Email, *user)
		procError(t, err)

		ts := httptest.NewServer(http.HandlerFunc(j.jwtSuperadminAuth(u.Repository, adminService.PromoteToAdmin)))
		defer ts.Close()

		params := map[string]interface{}{
			"email": user.Email,
		}

		request, err := http.NewRequest(http.MethodPut, ts.URL, prepareParams(t, params))
		request.Header.Set("Authorization", "Bearer "+jwt)

		resp := doRequest(request, err)
		assertStatus(t, 422, resp)
		assertBody(t, "cannot promote this user", resp)
	})

	t.Run("invalid email", func(t *testing.T) {
		u, adminService, j, _, _, _, jwt := InitUser(t)

		ts := httptest.NewServer(http.HandlerFunc(j.jwtSuperadminAuth(u.Repository, adminService.PromoteToAdmin)))
		defer ts.Close()

		params := map[string]interface{}{
			"email": "sad;las",
		}

		request, err := http.NewRequest(http.MethodPut, ts.URL, prepareParams(t, params))
		request.Header.Set("Authorization", "Bearer "+jwt)

		resp := doRequest(request, err)
		assertStatus(t, 422, resp)
		assertBody(t, "email not valid", resp)
	})
}

func TestAdminFire(t *testing.T) {
	doRequest := createRequester(t)

	t.Run("admin fires", func(t *testing.T) {
		u, adminService, j, user, _, _, jwt := InitUser(t)

		user.Role = "admin"
		err := u.Repository.Update(user.Email, *user)
		procError(t, err)

		ts := httptest.NewServer(http.HandlerFunc(j.jwtSuperadminAuth(u.Repository, adminService.FireAdmin)))
		defer ts.Close()

		params := map[string]interface{}{
			"email": user.Email,
		}

		request, err := http.NewRequest(http.MethodPut, ts.URL, prepareParams(t, params))
		request.Header.Set("Authorization", "Bearer "+jwt)

		resp := doRequest(request, err)
		assertStatus(t, 200, resp)
		assertBody(t, "fired", resp)

		fired, err := u.Repository.Get(user.Email)
		if err != nil {
			t.Error(err)
			return
		}
		if fired.Role != "user" {
			t.Errorf("fired user is still admin")
		}
	})

	t.Run("admin cannot fire admin", func(t *testing.T) {
		u, adminService, j, user, _, jwt, _ := InitUser(t)

		user.Role = "admin"
		err := u.Repository.Update(user.Email, *user)
		procError(t, err)

		otherAdmin := User{
			Email:          "exampm@mail.com",
			PasswordDigest: "",
			Role:           "admin",
		}
		err = u.Repository.Add(otherAdmin.Email, otherAdmin)
		procError(t, err)

		ts := httptest.NewServer(http.HandlerFunc(j.jwtSuperadminAuth(u.Repository, adminService.FireAdmin)))
		defer ts.Close()

		params := map[string]interface{}{
			"email": otherAdmin.Email,
		}

		request, err := http.NewRequest(http.MethodPut, ts.URL, prepareParams(t, params))
		request.Header.Set("Authorization", "Bearer "+jwt)

		resp := doRequest(request, err)
		assertStatus(t, 401, resp)
		assertBody(t, "access denied", resp)
	})

	t.Run("superadmin cannot fire user", func(t *testing.T) {
		u, adminService, j, user, _, _, jwt := InitUser(t)

		ts := httptest.NewServer(http.HandlerFunc(j.jwtSuperadminAuth(u.Repository, adminService.FireAdmin)))
		defer ts.Close()

		params := map[string]interface{}{
			"email": user.Email,
		}

		request, err := http.NewRequest(http.MethodPut, ts.URL, prepareParams(t, params))
		request.Header.Set("Authorization", "Bearer "+jwt)

		resp := doRequest(request, err)
		assertStatus(t, 422, resp)
		assertBody(t, "cannot fire this user", resp)
	})

	t.Run("invalid email", func(t *testing.T) {
		u, adminService, j, _, _, _, jwt := InitUser(t)

		ts := httptest.NewServer(http.HandlerFunc(j.jwtSuperadminAuth(u.Repository, adminService.FireAdmin)))
		defer ts.Close()

		params := map[string]interface{}{
			"email": "sad;las",
		}

		request, err := http.NewRequest(http.MethodPut, ts.URL, prepareParams(t, params))
		request.Header.Set("Authorization", "Bearer "+jwt)

		resp := doRequest(request, err)
		assertStatus(t, 422, resp)
		assertBody(t, "email not valid", resp)
	})
}
