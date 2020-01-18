package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"text/template"

	rice "github.com/GeertJohan/go.rice"
	"github.com/go-zoo/bone"
	"github.com/gorilla/csrf"
	"gopkg.in/yaml.v2"
)

// Config ...
type Config struct {
	HTTP struct {
		Port       int    `yaml:"port"`
		ServerCert string `yaml:"server_crt"`
		ServerKey  string `yaml:"server_key"`
		CSRFKey    string `yaml:"csrf_key"`
		CSRFSecure bool   `yaml:"csrf_secure"`
	} `yaml:"http"`
	ReCAPTCHA struct {
		VerifyURL string `yaml:"verify_url"`
		ClientKey string `yaml:"client_key"`
		ServerKey string `yaml:"server_key"`
	} `yaml:"recaptcha"`
}

// GoogleRecaptchaResponse ...
type GoogleRecaptchaResponse struct {
	Success            bool     `json:"success"`
	ChallengeTimestamp string   `json:"challenge_ts"`
	Hostname           string   `json:"hostname"`
	ErrorCodes         []string `json:"error-codes"`
}

var configuration Config
var viewBox *rice.Box

func main() {
	pid := os.Getpid()
	err := ioutil.WriteFile("application.pid", []byte(strconv.Itoa(pid)), 0666)
	if err != nil {
		log.Fatal(err)
	}

	var configLocation string
	flag.StringVar(&configLocation, "config", ".config.yml", "Set the location of the configuration file")
	flag.Parse()
	loadConfiguration(configLocation, &configuration) // Load the configuration for yaml file

	viewBox = rice.MustFindBox("views")
	staticBox := rice.MustFindBox("static")
	staticFileServer := http.StripPrefix("/static/", http.FileServer(staticBox.HTTPBox()))

	port := strconv.Itoa(configuration.HTTP.Port)
	if os.Getenv("ASPNETCORE_PORT") != "" {
		port = os.Getenv("ASPNETCORE_PORT") // Override port if deployed in IIS via ASPNETCOREMODULE
	}

	if len(configuration.ReCAPTCHA.ServerKey) < 0 {
		log.Fatalln("Missing ReCAPTCHA.ServerKey from .config.yml")
	}

	if len(configuration.ReCAPTCHA.ClientKey) < 0 {
		log.Fatalln("Missing ReCAPTCHA.ClientKey from .config.yml")
	}

	CSRF := csrf.Protect(
		[]byte(configuration.HTTP.CSRFKey),
		csrf.Secure(configuration.HTTP.CSRFSecure),
	)

	router := bone.New()
	router.Handle("/static/", staticFileServer)
	router.HandleFunc("/", journalHandler)
	log.Fatal(http.ListenAndServe(":"+port, CSRF(router)))
}

func renderPage(w http.ResponseWriter, r *http.Request, hasError bool, errorMessage string) error {
	base, err := viewBox.String("base.html")
	if err != nil {
		log.Panic(err.Error())
	}

	content, err := viewBox.String("index.html")
	if err != nil {
		log.Panic(err.Error())
	}

	x, err := template.New("base").Parse(base)
	if err != nil {
		log.Panic(err.Error())
	}

	x.New("content").Parse(content)
	if err != nil {
		log.Panic(err.Error())
	}

	err = x.Execute(w, map[string]interface{}{
		"Title":        "Demo Using reCAPTCHA with Golang | John Pili",
		"csrfToken":    csrf.Token(r),
		"clientKey":    configuration.ReCAPTCHA.ClientKey,
		"hasError":     hasError,
		"errorMessage": errorMessage,
	})
	return err
}

func renderResult(w http.ResponseWriter, r *http.Request, title string, payload string) error {
	base, err := viewBox.String("base.html")
	if err != nil {
		log.Panic(err.Error())
	}

	content, err := viewBox.String("result.html")
	if err != nil {
		log.Panic(err.Error())
	}

	x, err := template.New("base").Parse(base)
	if err != nil {
		log.Panic(err.Error())
	}

	x.New("content").Parse(content)
	if err != nil {
		log.Panic(err.Error())
	}

	err = x.Execute(w, map[string]interface{}{
		"Title":       "Demo Using reCAPTCHA with Golang | John Pili",
		"csrfToken":   csrf.Token(r),
		"postTitle":   title,
		"postPayload": payload,
	})
	return err
}

func journalHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		{
			err := renderPage(w, r, false, "")
			if err != nil {
				log.Panic(err.Error())
			}
		}
	case http.MethodPost:
		{
			if err := r.ParseForm(); err != nil {
				fmt.Fprintf(w, "ParseForm() err: %v", err)
				return
			}
			if len(r.FormValue("g-recaptcha-response")) == 0 {
				_ = renderPage(w, r, true, "g-recaptcha-response is missing")
				return
			}

			result, err := validateReCAPTCHA(r.FormValue("g-recaptcha-response"))
			if err != nil {
				_ = renderPage(w, r, true, err.Error())
				return
			}

			if !result {
				_ = renderPage(w, r, true, "reCAPTCHA is not valid")
				return
			}

			_ = renderResult(w, r, r.FormValue("title"), r.FormValue("payload"))
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
	body, err := ioutil.ReadAll(req.Body) // Read the response from Google
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

// This handles the configuration loader for YAML
func loadConfiguration(location string, c *Config) {
	f, err := os.Open(location)
	if err != nil {
		log.Fatal(err)
	}

	decoder := yaml.NewDecoder(f)
	err = decoder.Decode(&c)
	if err != nil {
		log.Fatal(err)
	}
}
