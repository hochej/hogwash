package cloudflareapitoken

import "net/http"

func verify(_ *http.Client) string {
	return "https://api.cloudflare.com/client/v4/user/tokens/verify"
}
