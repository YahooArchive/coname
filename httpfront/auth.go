package httpfront

import (
	"net/http"
)

func auth(r *http.Request) (string, error) {
	// TODO: add auth logic specific to httpfront here, if any
	return "", nil
}
