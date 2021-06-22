package rlimit

import (
	"net/http"
	"strings"
	"time"
)

type RateLimit struct {
	Requests  int
	TimeFrame time.Duration
	IPAccess  map[string]*Request
}

type Request struct {
	Last  time.Time
	Total int
}

func New(requests int, timeframe time.Duration) *RateLimit {
	return &RateLimit{
		Requests:  requests,
		TimeFrame: timeframe,
		IPAccess:  make(map[string]*Request),
	}
}

func (rl *RateLimit) Limit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := getIP(r)
		req, ok := rl.IPAccess[ip]
		now := time.Now().UTC()
		if !ok {
			req = &Request{Last: now}
			rl.IPAccess[ip] = req
		}
		if now.After(req.Last.Add(rl.TimeFrame)) {
			req.Last = now
			req.Total = 0
		}
		if req.Total > rl.Requests {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		req.Total++
		next.ServeHTTP(w, r)
	})
}

func getIP(r *http.Request) string {
	var ip string
	ff := r.Header.Get("X-Forwarded-For")
	if ff != "" {
		p := strings.Split(ff, " ")
		ip = p[len(p)-1]
	} else {
		ip = strings.Split(r.RemoteAddr, ":")[0]
	}
	return ip
}
