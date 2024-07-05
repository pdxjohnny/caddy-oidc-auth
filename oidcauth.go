package oidcauth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/coreos/go-oidc"
	"github.com/golang-jwt/jwt"
	"golang.org/x/oauth2"
)

func init() {
	caddy.RegisterModule(OIDCAuth{})
}

type OIDCAuth struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	Issuer       string `json:"issuer"`
	RedirectURL  string `json:"redirect_url"`
	Audience     string `json:"audience"`
}

func (OIDCAuth) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.oidcauth",
		New: func() caddy.Module { return new(OIDCAuth) },
	}
}

func (oa *OIDCAuth) Provision(ctx caddy.Context) error {
	return nil
}

func (oa *OIDCAuth) Validate() error {
	if oa.ClientID == "" {
		return fmt.Errorf("client_id is required")
	}
	if oa.ClientSecret == "" {
		return fmt.Errorf("client_secret is required")
	}
	if oa.Issuer == "" {
		return fmt.Errorf("issuer is required")
	}
	if oa.RedirectURL == "" {
		return fmt.Errorf("redirect_url is required")
	}

	_, err := oidc.NewProvider(context.Background(), oa.Issuer)
	if err != nil {
		return fmt.Errorf("failed to connect to issuer: %v", err)
	}

	return nil
}

func (oa OIDCAuth) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	provider, err := oidc.NewProvider(context.Background(), oa.Issuer)
	if err != nil {
		return err
	}

	oauth2Config := oauth2.Config{
		ClientID:     oa.ClientID,
		ClientSecret: oa.ClientSecret,
		RedirectURL:  oa.RedirectURL,
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}

	// Get the ID token from the request (you may need to adjust this depending on your specific setup)
	idToken := r.Header.Get("Authorization")
	if idToken == "" {
		state, err := generateRandomState(32)
		if err != nil {
			return err
		}

		http.SetCookie(w, &http.Cookie{
			Name:     "oidc_state",
			Value:    state,
			Path:     "/",
			HttpOnly: true,
			Secure:   true,
		})

		http.Redirect(w, r, oauth2Config.AuthCodeURL(state), http.StatusFound)
		return nil
	}

	// Extract the token from the "Bearer" scheme
	parts := strings.Split(idToken, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		return caddyhttp.Error(http.StatusUnauthorized, fmt.Errorf("invalid authorization header format"))
	}
	idToken = parts[1]

	// Parse and validate the ID token
	token, err := jwt.Parse(idToken, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		// Use the key from the provider to validate the token
		keySet := oidc.NewRemoteKeySet(context.Background(), oa.Issuer+"/.well-known/jwks.json")
		key, err := keySet.VerifySignature(context.Background(), idToken)
		return key, err
	})
	if err != nil {
		return caddyhttp.Error(http.StatusUnauthorized, fmt.Errorf("failed to verify id_token: %v", err))
	}

	// Determine the expected audience
	expectedAudience := oa.Audience
	if expectedAudience == "" {
		expectedAudience = r.Host
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		// Validate the audience
		audience := claims["aud"].(string)
		if audience != expectedAudience {
			return caddyhttp.Error(http.StatusUnauthorized, fmt.Errorf("invalid audience"))
		}
	} else {
		return caddyhttp.Error(http.StatusUnauthorized, fmt.Errorf("invalid token claims"))
	}

	// Continue with the next handler
	return next.ServeHTTP(w, r)
}

func (oa *OIDCAuth) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		for d.NextBlock(0) {
			switch d.Val() {
			case "client_id":
				if !d.Args(&oa.ClientID) {
					return d.ArgErr()
				}
			case "client_secret":
				if !d.Args(&oa.ClientSecret) {
					return d.ArgErr()
				}
			case "issuer":
				if !d.Args(&oa.Issuer) {
					return d.ArgErr()
				}
			case "redirect_url":
				if !d.Args(&oa.RedirectURL) {
					return d.ArgErr()
				}
			case "audience":
				if !d.Args(&oa.Audience) {
					return d.ArgErr()
				}
			}
		}
	}
	return nil
}

func generateRandomState(length int) (string, error) {
	b := make([]byte, length)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// Interface guards
var (
	_ caddyhttp.MiddlewareHandler = (*OIDCAuth)(nil)
	_ caddyfile.Unmarshaler       = (*OIDCAuth)(nil)
)
