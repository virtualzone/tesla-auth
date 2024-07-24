package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"slices"
	"strings"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
)

type TeslaAPITokenReponse struct {
	RefreshToken string `json:"refresh_token"`
	AccessToken  string `json:"access_token"`
}

var authStateCache map[string]time.Time = make(map[string]time.Time)

func main() {
	log.Println("Starting Tesla Auth Server...")
	serveHTTP()
}

func sendBadRequest(w http.ResponseWriter) {
	w.WriteHeader(http.StatusBadRequest)
}

func sendNotFound(w http.ResponseWriter) {
	w.WriteHeader(http.StatusNotFound)
}

func servePublicKey(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, GetConfig().PublicKeyPath)
}

func initAuthRequest(w http.ResponseWriter, r *http.Request) {
	scope := []string{
		"openid",
		"vehicle_device_data",
		"vehicle_charging_cmds",
		"offline_access",
	}
	params := url.Values{}
	params.Add("client_id", GetConfig().TeslaClientID)
	params.Add("prompt", "login")
	params.Add("redirect_uri", getAuthRedirectURI())
	params.Add("response_type", "code")
	params.Add("scope", strings.Join(scope, " "))
	params.Add("state", createAuthState())

	w.Header().Set("Location", "https://auth.tesla.com/oauth2/v3/authorize?"+params.Encode())
	w.WriteHeader(http.StatusTemporaryRedirect)
}

func authCallback(w http.ResponseWriter, r *http.Request) {
	cleanupExpiredAuthCodes()
	state := r.URL.Query().Get("state")
	_, ok := authStateCache[state]
	if !ok {
		sendNotFound(w)
		return
	}

	tokens, err := getAuthTokens(r.URL.Query().Get("code"), getAuthRedirectURI())
	if err != nil {
		log.Println(err)
		sendBadRequest(w)
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(tokens.AccessToken))
}

func getAuthTokens(code string, redirectURI string) (*TeslaAPITokenReponse, error) {
	target := "https://auth.tesla.com/oauth2/v3/token"
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("client_id", GetConfig().TeslaClientID)
	data.Set("client_secret", GetConfig().TeslaClientSecret)
	data.Set("code", code)
	data.Set("redirect_uri", redirectURI)
	data.Set("audience", GetConfig().TeslaAudience)
	r, _ := http.NewRequest("POST", target, strings.NewReader(data.Encode()))
	r.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	resp, err := retryHTTPRequest(r)
	if err != nil {
		log.Println(err)
		return nil, err
	}

	var m TeslaAPITokenReponse
	if err := unmarshalBody(resp.Body, &m); err != nil {
		return nil, err
	}

	parsedToken, _ := jwt.Parse(m.AccessToken, nil)
	if parsedToken == nil || parsedToken.Claims == nil {
		return nil, errors.New("could not parse jwt")
	}

	return &m, nil
}

func getAuthRedirectURI() string {
	if strings.Contains(GetConfig().Hostname, "localhost") {
		return "http://" + GetConfig().Hostname + "/auth/callback"
	}
	return "https://" + GetConfig().Hostname + "/auth/callback"
}

func createAuthState() string {
	res := uuid.NewString()
	authStateCache[res] = time.Now().Add(5 * time.Minute)
	log.Println(authStateCache)
	return res
}

func cleanupExpiredAuthCodes() {
	now := time.Now()
	for k, v := range authStateCache {
		if now.After(v) {
			delete(authStateCache, k)
		}
	}
}

func unmarshalBody(r io.ReadCloser, o interface{}) error {
	if r == nil {
		return errors.New("body is NIL")
	}
	defer r.Close()
	body, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	if err = json.Unmarshal(body, &o); err != nil {
		return err
	}
	return nil
}

func retryHTTPRequest(req *http.Request) (*http.Response, error) {
	isRetryCode := func(code int) bool {
		retryCodes := []int{405, 408, 412}
		return slices.Contains(retryCodes, code)
	}

	client := &http.Client{}
	retryCounter := 1
	var resp *http.Response
	var err error
	for retryCounter <= 3 {
		resp, err = client.Do(req)
		if err != nil || (resp != nil && isRetryCode(resp.StatusCode)) {
			time.Sleep(2 * time.Second)
			retryCounter++
		} else {
			retryCounter = 999
		}
	}
	return resp, err
}

func serveHTTP() {
	router := mux.NewRouter()
	router.HandleFunc("/.well-known/appspecific/com.tesla.3p.public-key.pem", servePublicKey).Methods("GET")
	router.HandleFunc("/auth/init", initAuthRequest).Methods("GET")
	router.HandleFunc("/auth/callback", authCallback).Methods("GET")

	httpServer := &http.Server{
		Addr:         fmt.Sprintf("0.0.0.0:%d", GetConfig().Port),
		WriteTimeout: time.Second * 15,
		ReadTimeout:  time.Second * 15,
		IdleTimeout:  time.Second * 60,
		Handler:      router,
	}

	go func() {
		if err := httpServer.ListenAndServe(); err != nil {
			log.Fatal(err)
			os.Exit(-1)
		}
	}()
	log.Println("HTTP Server listening")

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	<-c
	log.Println("Shutting down...")
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*15)
	defer cancel()
	httpServer.Shutdown(ctx)
}
