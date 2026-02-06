package csrf

import "net/http"

func CSRFMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodDelete {
			csrfCookie, err1 := r.Cookie("csrf_token")

			// Try header first, fallback to form
			csrfToken := r.Header.Get("X-CSRF-Token")
			if csrfToken == "" {
				_ = r.ParseForm() // Make sure form data is parsed
				csrfToken = r.FormValue("csrf_token")
			}

			if err1 != nil || csrfToken == "" || csrfCookie.Value != csrfToken {
				http.Error(w, "Invalid CSRF token", http.StatusForbidden)
				return
			}
		}

		next.ServeHTTP(w, r)
	}
}
