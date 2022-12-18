package main

import (
	"fmt"
	"github.com/johnpili/golang-with-recaptcha/models"
	"github.com/johnpili/golang-with-recaptcha/page"
	"gopkg.in/yaml.v2"
	"html/template"
	"log"
	"math/rand"
	"net/http"
	"os"
	"time"
)

const (
	FreeMono   = "FreeMono.ttf"
	FreeSans   = "FreeSans.ttf"
	UbuntuMono = "UbuntuMono-R.ttf"
)

func renderPage(w http.ResponseWriter, r *http.Request, vm interface{}, basePath string, filenames ...string) {
	p := vm.(*page.Page)

	if p.Data == nil {
		p.SetData(make(map[string]interface{}))
	}

	if p.ErrorMessages == nil {
		p.ResetErrors()
	}

	if p.UIMapData == nil {
		p.UIMapData = make(map[string]interface{})
	}
	p.UIMapData["basePath"] = basePath
	templateFS := template.Must(template.New("base").ParseFS(views, filenames...))
	err := templateFS.Execute(w, p)
	if err != nil {
		log.Panic(err.Error())
	}
}

// This will handle the loading of config.yml
func loadConfiguration(a string, b *models.Config) {
	f, err := os.Open(a)
	if err != nil {
		log.Fatal(err.Error())
	}

	decoder := yaml.NewDecoder(f)
	err = decoder.Decode(b)
	if err != nil {
		log.Fatal(err.Error())
	}
}

func generateRandomBytes(length int) []byte {
	s := ""
	for i := 33; i <= 126; i++ {
		s = s + fmt.Sprintf("%c", i)
	}
	rs := make([]byte, 0)
	rand.Seed(time.Now().UnixNano())
	for i := 0; i < length; i++ {
		delta := rand.Intn(len(s))
		rs = append(rs, s[delta])
	}
	return rs
}
