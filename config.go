package trojan

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
)

type Config struct {
	Type *RunType `json:"run_type"`

	LocalAddr string   `json:"local_addr"`
	LocalPort uint16   `json:"local_port"`
	Password  []string `json:"password"`

	SSL *SSLConfig `json:"ssl"`

	AutoCert *AutoCert `json:"autocert"`
	WebRoot  string    `json:"web_root"`
}

func ParseConfig(name string) (*Config, error) {
	cfg := &Config{}

	if _, err := os.Stat(name); os.IsNotExist(err) {
		return nil, fmt.Errorf("config file %s not found", name)
	}

	fs, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer fs.Close()

	dec := json.NewDecoder(fs)
	err = dec.Decode(cfg)
	if err != nil {
		return nil, err
	}

	return cfg, nil
}

// Validate config and set some default config
func (cfg *Config) Validate() error {
	ac := cfg.AutoCert
	ssl := cfg.SSL

	if !ac.Enabled &&
		ssl.Key == "" && ssl.Cert == "" {
		return errors.New("please provide cert and key, or use autocert")
	}

	if ac.Enabled {
		if ac.Domain == "" {
			return errors.New("when enabled autocert, domain required")
		}
	}

	return nil
}

type RunType int

const (
	RunTypeServer RunType = iota + 1
	RunTypeClient
	RunTypeForward
	RunTypeNat
)

type runTypeMap struct {
	key   []byte
	value RunType
}

func (m runTypeMap) keyEq(k []byte) bool {
	return bytes.Equal(m.key, k)
}

var runTypeMaps = [...]runTypeMap{
	{[]byte("server"), RunTypeServer},
	{[]byte("client"), RunTypeClient},
	{[]byte("forward"), RunTypeForward},
	{[]byte("nat"), RunTypeNat},
}

func (rt *RunType) UnmarshalJSON(b []byte) error {

	for _, m := range runTypeMaps {
		// notice b is "server"
		ok := m.keyEq(b[1 : len(b)-1])
		if ok {
			*rt = m.value
			return nil
		}
	}

	return fmt.Errorf("run type %s undefined", b)
}

// func (rt *RunType) MarshalJSON() ([]byte, error) {}

type SSLConfig struct {
	Cert        string `json:"cert"`
	Key         string `json:"key"`
	KeyPassword string `json:"key_password"`

	Alpn []string `json:"alpn"`
}

type TCPConfig struct {
	PreferIPv4   bool `json:"prefer_ipv4"`
	NoDelay      bool `json:"no_delay"`
	KeepAlive    bool `json:"keep_alive"`
	ReusePort    bool `json:"reuse_port"`
	FastOpen     bool `json:"fast_open"`
	FastOpenQlen int  `json:"fast_open_qlen"`
}

type MySQLConfig struct {
	Enabled    bool   `json:"enabled"`
	ServerAddr string `json:"server_addr"`
	ServerPort uint16 `json:"server_port"`
	Database   string `json:"database"`
	Username   string `json:"username"`
	Password   string `json:"password"`
	Key        string `json:"key"`
	Cert       string `json:"cert"`
	Ca         string `json:"ca"`
}

type AutoCert struct {
	Enabled bool   `json:"enabled"`
	Domain  string `json:"domain"`
	Email   string `json:"email"`
	CFToken string `json:"cf_token"`
	Path    string `json:"path"`
}
