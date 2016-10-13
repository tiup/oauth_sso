package oauthsso

import (
	"crypto/rand"
	"encoding/base64"
	"io"
	"net/http"
	"net/url"
	"strings"
	"net/http/httputil"
)

type Server struct {
	config   *Config
}

func NewServer(cfg *Config) *Server {
	return &Server{
		config:   cfg,
	}
}

func (this *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	nocache(w)
	switch r.URL.Path {
	case "/sso/login":
		this.login(w, r)
	case "/sso/logout":
		this.logout(w, r)
	case "/sso/callback":
		this.callback(w, r)
	case "/sso/introspect":
		this.introspect(w, r)
	default:
		http.NotFoundHandler().ServeHTTP(w, r)
	}
}


func (this *Server) login(w http.ResponseWriter, r *http.Request) {
	redirectURL := this.config.Oauth.RedirectURL
	if this.config.Oauth.RedirectURL == "" {
		if host := r.Header.Get("X-Forwarded-Host"); host != "" {
			redirectURL = r.Header.Get("X-Forwarded-Proto") + "://" + host
		} else {
			redirectURL = "http://" + r.Host
			if r.TLS != nil {
				redirectURL = "https://" + r.Host
			}
		}
		redirectURL += "/sso/callback"
	}
	if strings.Contains(this.config.Oauth.RedirectURL, "?") {
		redirectURL += "&"
	} else {
		redirectURL += "?"
	}
	redirectURL += r.URL.RawQuery
	csrfToken := randomString(12)
	query := r.URL.Query()
	authorizeUrl := this.config.Oauth.AuthCodeURL(csrfToken, redirectURL, query)
	cookie := &http.Cookie{
		Name:     "csrf_token",
		Value:    csrfToken,
		HttpOnly: true,
		MaxAge:   3600,
	}
	for k, v := range this.config.CookieHostMapper {
		if strings.HasSuffix(r.Host, k) {
			cookie.Domain = v
		}
	}
	http.SetCookie(w, cookie)
	http.Redirect(w, r, authorizeUrl, http.StatusFound)
}

func (this *Server) callback(w http.ResponseWriter, r *http.Request) {
	redirectUri := r.FormValue("redirect_uri")
	if redirectUri == "" {
		redirectUri = "/"
	}
	redirectURL, _ := url.Parse(redirectUri)
	query := redirectURL.Query()
	if err := r.FormValue("error"); err != "" {
		query.Set("error", "access_denied")
		query.Set("error_description", err)
		redirectURL.RawQuery = query.Encode()
		http.Redirect(w, r, redirectURL.String(), http.StatusFound)
		return
	}
	state := r.FormValue("state")
	if !cookieMatch(r, "csrf_token", state) {
		query.Set("error", "access_denied")
		query.Set("error_description", "csrf token does not match state")
		redirectURL.RawQuery = query.Encode()
		http.Redirect(w, r, redirectURL.String(), http.StatusFound)
		return
	}
	authorizationCode := r.FormValue("code")
	token, err := this.config.Oauth.ExchangeToken(authorizationCode)
	if err != nil {
		query.Set("error", "access_denied")
		query.Set("error_description", err.Error())
		redirectURL.RawQuery = query.Encode()
		http.Redirect(w, r, redirectURL.String(), http.StatusFound)
		return
	}
	cookie := &http.Cookie{
		Name:   "access_token",
		Value:  token.AccessToken,
		Path:   "/",
		MaxAge: 0,
	}
	for k, v := range this.config.CookieHostMapper {
		if strings.HasSuffix(r.Host, k) {
			cookie.Domain = v
		}
	}
	http.SetCookie(w, cookie)
	if r.FormValue("sso_proxy") == "true" {
		iFrameRedirect(w, redirectUri)
		return
	}
	http.Redirect(w, r, redirectUri, http.StatusFound)
}

func (this *Server) logout(w http.ResponseWriter, r *http.Request) {
	if ck, err := r.Cookie("access_token"); err == nil {
		if ck.Value != "" {
			res, _ := http.Get(this.config.Oauth.Endpoint.RevokeURL + "?access_token=" + ck.Value)
			defer res.Body.Close()
		}
	}
	cookie := &http.Cookie{
		Name:   "access_token",
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	}
	for k, v := range this.config.CookieHostMapper {
		if strings.HasSuffix(r.Host, k) {
			cookie.Domain = v
		}
	}
	http.SetCookie(w, cookie)
	redirectUri := r.FormValue("redirect_uri")
	if redirectUri == "" {
		redirectUri = "http://" + r.Host
		if r.Header.Get("X-Forwarded-Proto") == "https" || r.TLS != nil {
			redirectUri = "https://" + r.Host
		}
	}

	URL, _ := url.Parse(this.config.Account.LogoutURL)
	query := url.Values{
		"redirect_uri": {redirectUri},
	}
	URL.RawQuery = query.Encode()
	http.Redirect(w, r, URL.String(), http.StatusFound)
}

type Config struct {
	Oauth      OauthConfig
	Account    struct {
		LogoutURL string
	}
	CookieHostMapper map[string]string
}

func randomString(size int) string {
	uuid := make([]byte, size)
	io.ReadFull(rand.Reader, uuid)
	return base64.URLEncoding.EncodeToString([]byte(uuid))
}

func nocache(w http.ResponseWriter) {
	w.Header().Add(
		"Cache-Control", "no-cache, no-store, max-age=0, must-revalidate",
	)
	w.Header().Add("Pragma", "no-cache")
	w.Header().Add("Expires", "Fri, 01 Jan 1990 00:00:00 GMT")
}
func iFrameRedirect(w http.ResponseWriter, redirectUri string) {
	out := `<head><script>window.parent.window.location = "` + redirectUri + `"</script></head>`
	w.Write([]byte(out))
}

func cookieMatch(req *http.Request, name, value string) bool {
	for _, c := range req.Cookies() {
		if c.Name == name && c.Value == value {
			return true
		}
	}
	return false
}

func (this *Server) introspect(w http.ResponseWriter, r *http.Request) {
	ck, err := r.Cookie("access_token")
	if err != nil || ck.Value == "" {
		http.Redirect(w,r,"/sso/login?redirect_uri=/sso/introspect" ,302)
		return
	}

	introUrl , err := url.Parse(this.config.Oauth.Endpoint.IntrospectURL)
	if err != nil {
		w.Write([]byte("config error"))
		return
	}

	r.Header.Set("Authorization", "Bearer " + ck.Value)
	r.URL = introUrl
	r.Host = introUrl.Host
	rp := &httputil.ReverseProxy{Director: func(req *http.Request) {
		req = r
	}}
	rp.ServeHTTP(w, r)
}
