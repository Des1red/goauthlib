package authError

import (
	"net/http"
)

type ErrorHandler func(w http.ResponseWriter, r *http.Request, err error)

var errorHandler ErrorHandler = defaultErrorHandler

func defaultErrorHandler(w http.ResponseWriter, _ *http.Request, err error) {
	switch err {
	case ErrUnauthorized:
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	case ErrForbidden:
		http.Error(w, "forbidden", http.StatusForbidden)
	default:
		http.Error(w, "server error", http.StatusInternalServerError)
	}
}

func SetErrorHandler(h ErrorHandler) {
	if h != nil {
		errorHandler = h
	}
}

func Handle(w http.ResponseWriter, r *http.Request, err error) {
	errorHandler(w, r, err)
}
