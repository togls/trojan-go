package trojan

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	"github.com/caddyserver/certmagic"
	"github.com/libdns/cloudflare"
	"github.com/mholt/acmez/acme"

	"github.com/togls/trojan-go/log"
)

func TlsConfig(ctx context.Context, cfg *Config) (*tls.Config, error) {
	c := &tls.Config{}
	if !cfg.AutoCert.Enabled {
		cert, err := loadKeyPair(cfg.SSL.Cert, cfg.SSL.Key, cfg.SSL.KeyPassword)
		if err != nil {
			return nil, fmt.Errorf("tls config, %w", err)
		}

		c.Certificates = []tls.Certificate{*cert}
		c.NextProtos = cfg.SSL.Alpn

		return c, nil
	}

	certmagic.DefaultACME.Agreed = true
	certmagic.DefaultACME.Email = cfg.AutoCert.Email
	certmagic.DefaultACME.DisableHTTPChallenge = false
	certmagic.DefaultACME.DisableTLSALPNChallenge = false
	magic := certmagic.NewDefault()

	zeroSSL := certmagic.NewACMEIssuer(&certmagic.Default, certmagic.ACMEIssuer{
		CA:     certmagic.ZeroSSLProductionCA,
		Email:  cfg.AutoCert.Email,
		Agreed: true,
		DNS01Solver: &certmagic.DNS01Solver{
			DNSProvider: &cloudflare.Provider{
				APIToken: cfg.AutoCert.CFToken,
			},
		},
	})

	zeroSSL.NewAccountFunc = func(ctx context.Context, _ *certmagic.ACMEIssuer, acct acme.Account) (acme.Account, error) {
		endpoint := "https://api.zerossl.com/acme/eab-credentials-email"
		form := url.Values{"email": []string{cfg.AutoCert.Email}}
		body := strings.NewReader(form.Encode())
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, body)
		if err != nil {
			return acct, fmt.Errorf("forming request: %w", err)
		}

		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("User-Agent", certmagic.UserAgent)

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return acct, fmt.Errorf("performing EAB credentials request: %w", err)
		}
		defer resp.Body.Close()

		var result struct {
			Success bool `json:"success"`
			Error   struct {
				Code int    `json:"code"`
				Type string `json:"type"`
			} `json:"error"`
			EABKID     string `json:"eab_kid"`
			EABHMACKey string `json:"eab_hmac_key"`
		}

		err = json.NewDecoder(resp.Body).Decode(&result)
		if err != nil {
			return acct, fmt.Errorf("decoding API response: %w", err)
		}

		if result.Error.Code != 0 {
			return acct, fmt.Errorf("failed getting EAB credentials: HTTP %d: %s (code %d)",
				resp.StatusCode, result.Error.Type, result.Error.Code)
		}

		if resp.StatusCode != http.StatusOK {
			return acct, fmt.Errorf("failed getting EAB credentials: HTTP %d", resp.StatusCode)
		}

		zeroSSL.ExternalAccount = &acme.EAB{
			KeyID:  result.EABKID,
			MACKey: result.EABHMACKey,
		}

		return acct, nil
	}

	magic.Issuers = []certmagic.Issuer{zeroSSL}

	domains := []string{cfg.AutoCert.Domain}

	log.Info().Msgf("start attain cert for %s", domains)

	if err := magic.ManageSync(ctx, domains); err != nil {
		return nil, fmt.Errorf("manage sync, %w", err)
	}

	c = magic.TLSConfig()

	if cfg.SSL != nil && cfg.SSL.Alpn != nil {
		c.NextProtos = append(cfg.SSL.Alpn, c.NextProtos...)
	}
	// c.MinVersion = tls.VersionTLS13

	return c, nil
}

func loadKeyPair(kpath, cpath, pw string) (*tls.Certificate, error) {
	if pw == "" {
		kp, err := tls.LoadX509KeyPair(cpath, kpath)
		if err != nil {
			return nil, fmt.Errorf("load key pair, %w", err)
		}
		return &kp, nil
	}

	kFile, err := ioutil.ReadFile(kpath)
	if err != nil {
		return nil, fmt.Errorf("load key pair, %w", err)
	}

	kBlock, _ := pem.Decode(kFile)
	if kBlock == nil {
		return nil, fmt.Errorf("load key pair, key pem decode err")
	}

	decryptedKey, err := x509.DecryptPEMBlock(kBlock, []byte(pw))
	if err != nil {
		return nil, fmt.Errorf("load key pair, %w", err)
	}

	cFile, err := ioutil.ReadFile(cpath)
	if err != nil {
		return nil, fmt.Errorf("load key pair, %w", err)
	}

	cBlock, _ := pem.Decode(cFile)
	if cBlock == nil {
		return nil, fmt.Errorf("load key pair, cert pem decode err")
	}

	keyPair, err := tls.X509KeyPair(cBlock.Bytes, decryptedKey)
	if err != nil {
		return nil, fmt.Errorf("load key pair, %w", err)
	}

	return &keyPair, nil
}
