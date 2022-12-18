package models

// Config ...
type Config struct {
	HTTP struct {
		BasePath   string `yaml:"base_path"`
		Port       int    `yaml:"port"`
		IsTLS      bool   `yaml:"is_tls"`
		ServerCert string `yaml:"server_crt"`
		ServerKey  string `yaml:"server_key"`
	} `yaml:"http"`
	ReCAPTCHA struct {
		VerifyURL string `yaml:"verify_url"`
		ClientKey string `yaml:"client_key"`
		ServerKey string `yaml:"server_key"`
	} `yaml:"recaptcha"`
}
