package main

import (
	"embed"
	"encoding/json"
	"flag"
	"github.com/johnpili/golang-with-recaptcha/models"
	"github.com/johnpili/golang-with-recaptcha/page"
	"github.com/julienschmidt/httprouter"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"

	"github.com/gorilla/csrf"
)

// GoogleRecaptchaResponse ...
type GoogleRecaptchaResponse struct {
	Success            bool     `json:"success"`
	ChallengeTimestamp string   `json:"challenge_ts"`
	Hostname           string   `json:"hostname"`
	ErrorCodes         []string `json:"error-codes"`
}

var (
	configuration models.Config

	//go:embed views/*
	views embed.FS
)

func main() {
	pid := os.Getpid()
	err := os.WriteFile("application.pid", []byte(strconv.Itoa(pid)), 0666)
	if err != nil {
		log.Fatal(err)
	}

	var configLocation string
	flag.StringVar(&configLocation, "config", "config.yml", "Set the location of configuration file")
	flag.Parse()

	loadConfiguration(configLocation, &configuration)
	if len(configuration.ReCAPTCHA.ServerKey) == 0 {
		log.Fatalln("Missing ReCAPTCHA.ServerKey from .config.yml")
	}

	if len(configuration.ReCAPTCHA.ClientKey) == 0 {
		log.Fatalln("Missing ReCAPTCHA.ClientKey from .config.yml")
	}

	router := httprouter.New()
	router.HandlerFunc(http.MethodGet, "/", indexHandler)
	router.HandlerFunc(http.MethodPost, "/", indexHandler)

	csrfProtection := csrf.Protect(generateRandomBytes(32))
	port := strconv.Itoa(configuration.HTTP.Port)
	httpServer := &http.Server{
		Addr:         ":" + port,
		Handler:      csrfProtection(router),
		ReadTimeout:  120 * time.Second,
		WriteTimeout: 120 * time.Second,
	}

	if configuration.HTTP.IsTLS {
		log.Printf("Server running at https://localhost:%s%s/\n", port, configuration.HTTP.BasePath)
		log.Fatal(httpServer.ListenAndServeTLS(configuration.HTTP.ServerCert, configuration.HTTP.ServerKey))
		return
	}
	log.Printf("Server running at http://localhost:%s%s/\n", port, configuration.HTTP.BasePath)
	log.Fatal(httpServer.ListenAndServe())
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	p := page.New()
	p.Title = "Golang with reCAPTCHA"
	p.CSRFToken = csrf.Token(r)
	data := make(map[string]interface{})
	data["clientKey"] = configuration.ReCAPTCHA.ClientKey
	p.SetData(data)

	switch r.Method {
	case http.MethodGet:
		{
			p.SetData(data)
			renderPage(w, r, p, configuration.HTTP.BasePath, "views/base.html", "views/index.html")
		}
	case http.MethodPost:
		{
			if err := r.ParseForm(); err != nil {
				p.AddError(err.Error())
				renderPage(w, r, p, configuration.HTTP.BasePath, "views/base.html", "views/index.html")
				return
			}
			if len(r.FormValue("g-recaptcha-response")) == 0 {
				p.AddError("g-recaptcha-response is missing")
				renderPage(w, r, p, configuration.HTTP.BasePath, "views/base.html", "views/index.html")
				return
			}

			result, err := validateReCAPTCHA(r.FormValue("g-recaptcha-response"))
			if err != nil {
				p.AddError(err.Error())
				renderPage(w, r, p, configuration.HTTP.BasePath, "views/base.html", "views/index.html")
				return
			}

			if !result {
				p.AddError("reCAPTCHA is not valid")
				renderPage(w, r, p, configuration.HTTP.BasePath, "views/base.html", "views/index.html")
				return
			}

			data["postTitle"] = r.FormValue("title")
			data["postPayload"] = r.FormValue("payload")
			p.SetData(data)
			renderPage(w, r, p, configuration.HTTP.BasePath, "views/base.html", "views/result.html")
		}
	default:
		{
			log.Println("Unmapped HTTP Method")
			http.Redirect(w, r, "/?error", 303)
		}
	}
}

// This will handle the reCAPTCHA verification between your server to Google's server
func validateReCAPTCHA(recaptchaResponse string) (bool, error) {
	// Check this URL verification details from Google
	// https://developers.google.com/recaptcha/docs/verify
	req, err := http.PostForm(configuration.ReCAPTCHA.VerifyURL, url.Values{
		"secret":   {configuration.ReCAPTCHA.ServerKey},
		"response": {recaptchaResponse},
	})
	if err != nil { // Handle error from HTTP POST to Google reCAPTCHA verify server
		return false, err
	}
	defer req.Body.Close()
	body, err := io.ReadAll(req.Body) // Read the response from Google
	if err != nil {
		return false, err
	}

	var googleResponse GoogleRecaptchaResponse
	err = json.Unmarshal(body, &googleResponse) // Parse the JSON response from Google
	if err != nil {
		return false, err
	}
	return googleResponse.Success, nil
}
