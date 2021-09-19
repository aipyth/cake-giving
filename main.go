package main

import (
	"context"
	"crypto/md5"
	"log"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/gorilla/mux"
)

func wrapJwt(
	jwt *JWTService,
	f func(http.ResponseWriter, *http.Request, *JWTService),
) http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		f(rw, r, jwt)
	}
}

func addSuperadmin(s UserRepository) error {
	password := os.Getenv("CAKE_ADMIN_PASSWORD")
	passwordDigest := md5.New().Sum([]byte(password))
	superadmin := User{
		Email:          os.Getenv("CAKE_ADMIN_EMAIL"),
		PasswordDigest: string(passwordDigest),
		FavoriteCake:   "",
		Role:           "superadmin",
	}
	return s.Add(superadmin.Email, superadmin)
}

func GetCakeHandler(w http.ResponseWriter, r *http.Request, u User) {
	w.Write([]byte(u.FavoriteCake))
}

func main() {
	r := mux.NewRouter()

	users := NewInMemoryStorage()
	userService := UserService{
		Repository: users,
	}
	adminService := AdminService{
		Repository: users,
		BanHistory: NewInMemoryBanHistory(),
	}
	jwtService, err := NewJWTService("public.rsa", "privkey.rsa")
	if err != nil {
		panic(err)
	}

	addSuperadmin(users)

	// User handlers
	r.HandleFunc("/cake", logRequest(jwtService.jwtAuth(users, GetCakeHandler))).
		Methods(http.MethodGet)
	r.HandleFunc("/user/register", logRequest(userService.Register)).
		Methods(http.MethodPost)
	r.HandleFunc("/user/jwt", logRequest(wrapJwt(jwtService, userService.JWT))).
		Methods(http.MethodPost)
	r.HandleFunc("/user/favorite_cake", logRequest(jwtService.jwtAuth(users, userService.UpdateCake))).
		Methods(http.MethodPut)
	r.HandleFunc("/user/email", logRequest(jwtService.jwtAuth(users, userService.UpdateEmail))).
		Methods(http.MethodPut)
	r.HandleFunc("/user/password", logRequest(jwtService.jwtAuth(users, userService.UpdatePassword))).
		Methods(http.MethodPut)
	r.HandleFunc("/user/me", logRequest(jwtService.jwtAuth(users, userService.GetMe)))

	// Admin handlers
	r.HandleFunc("/admin/ban", logRequest(jwtService.jwtAdminAuth(users, adminService.BanUser))).
		Methods(http.MethodPost)
	r.HandleFunc("/admin/unban", logRequest(jwtService.jwtAdminAuth(users, adminService.UnbanUser))).
		Methods(http.MethodPost)
	r.HandleFunc("/admin/inspect", logRequest(jwtService.jwtAdminAuth(users, adminService.InspectUserBanHistory))).
		Methods(http.MethodGet)
	r.HandleFunc("/admin/promote", logRequest(jwtService.jwtSuperadminAuth(users, adminService.PromoteToAdmin))).
		Methods(http.MethodPost)
	r.HandleFunc("/admin/fire", logRequest(jwtService.jwtSuperadminAuth(users, adminService.FireAdmin))).
		Methods(http.MethodPost)

	srv := http.Server{
		Addr:    ":8080",
		Handler: r,
	}

	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt)
	go func() {
		<-interrupt
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		log.Println("Gracefully shutting down...")
		srv.Shutdown(ctx)
	}()

	log.Println("Server started, hit Ctrl+C to stop")
	err = srv.ListenAndServe()
	if err != nil {
		log.Println("Server exited with error:", err)
	}
	log.Println("Good bye :)")
}
