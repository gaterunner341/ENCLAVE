package web

import (
	"net/http"
	"strings"
)

// themeCookie remembers the appearance somebody chose. It is read on the server
// so that the correct palette is in the very first byte of HTML: a preference
// applied by script after the page has painted shows the wrong colours first,
// which is worse than not offering the choice.
const themeCookie = "enclave-theme"

// Themes are the three states offered. An empty value is "follow the system",
// which is the default and is stored by clearing the cookie rather than by
// recording a third value.
const (
	themeLight = "light"
	themeDark  = "dark"
)

// theme reads the chosen appearance from the request. Anything unrecognised is
// treated as no choice at all.
func theme(r *http.Request) string {
	c, err := r.Cookie(themeCookie)
	if err != nil {
		return ""
	}
	switch c.Value {
	case themeLight, themeDark:
		return c.Value
	}
	return ""
}

// handleTheme records the choice and returns to the page it was made on.
func (s *Server) handleTheme(w http.ResponseWriter, r *http.Request) {
	choice := strings.TrimSpace(r.FormValue("theme"))
	cookie := &http.Cookie{
		Name:     themeCookie,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		// A year, because an appearance preference that expires is a bug.
		MaxAge: 365 * 24 * 60 * 60,
	}
	switch choice {
	case themeLight, themeDark:
		cookie.Value = choice
	default:
		// Following the system is the absence of a choice, so it is stored by
		// removing the cookie rather than by recording a third value.
		cookie.Value = ""
		cookie.MaxAge = -1
	}
	http.SetCookie(w, cookie)
	http.Redirect(w, r, safeReturn(r.FormValue("return")), http.StatusSeeOther)
}

// safeReturn keeps the redirect on this site. The value comes from a form
// field, so a path that could send somebody elsewhere is discarded rather than
// followed.
func safeReturn(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" || !strings.HasPrefix(raw, "/") ||
		strings.HasPrefix(raw, "//") || strings.HasPrefix(raw, "/\\") ||
		strings.ContainsAny(raw, "\r\n") {
		return "/"
	}
	return raw
}
