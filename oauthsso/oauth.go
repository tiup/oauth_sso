package oauthsso

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
)

type OauthConfig struct {
	ClientID     string
	ClientSecret string
	Endpoint     struct {
		AuthURL   string
		TokenURL  string
		RevokeURL string
		IntrospectURL string
	}
	RedirectURL string
	Scopes      []string
}

func (c *OauthConfig) AuthCodeURL(state string, redirectURL string, query url.Values) string {
	var buf bytes.Buffer
	buf.WriteString(c.Endpoint.AuthURL)
	if query == nil {
		query = url.Values{}
	}
	query.Set("response_type", "code")
	query.Set("client_id", c.ClientID)
	query.Set("redirect_uri", redirectURL)
	query.Set("scope", strings.Join(c.Scopes, " "))
	query.Set("state", state)
	buf.WriteByte('?')
	buf.WriteString(query.Encode())
	return buf.String()
}

type Token struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
}

func (c *OauthConfig) ExchangeToken(code string) (*Token, error) {
	v := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"redirect_uri": {c.RedirectURL},
		"scope":        {strings.Join(c.Scopes, " ")},
	}
	req, err := http.NewRequest("POST", c.Endpoint.TokenURL, strings.NewReader(v.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accpet", "application/json")
	req.SetBasicAuth(c.ClientID, c.ClientSecret)
	r, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()
	body, err := ioutil.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("oauth2: cannot fetch token: %v", err)
	}
	if code := r.StatusCode; code < 200 || code > 299 {
		return nil, fmt.Errorf("oauth2: cannot fetch token: %v\nResponse: %s", r.Status, body)
	}

	token := new(Token)
	if err = json.Unmarshal(body, &token); err != nil {
		return nil, err
	}
	if token.AccessToken != "" {
		return token, nil
	}
	return nil, fmt.Errorf("oauth2: cannot fetch access token: %v\nResponse: %s", r.Status, body)
}
