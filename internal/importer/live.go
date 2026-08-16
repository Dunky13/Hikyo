package importer

import (
	"bytes"
	"errors"
	"net/http"
	"net/url"
)

// Shared live-provider transport and subprocess-output bounds. Both live
// connectors use these types, keeping response limits and redirect policy at
// one path instead of recreating them per provider.

var errLiveResponseTooLarge = errors.New("live provider response exceeds cap")

type cappedRoundTripper struct {
	next http.RoundTripper
}

func (c cappedRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	res, err := c.next.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	if res.ContentLength > MaxResponseBytes {
		res.Body.Close()
		return nil, errLiveResponseTooLarge
	}
	res.Body = http.MaxBytesReader(nil, res.Body, MaxResponseBytes)
	return res, nil
}

type refusedRedirect struct {
	from string
	to   string
}

func (e *refusedRedirect) Error() string { return "redirect refused" }

func originOf(u *url.URL) string {
	if u == nil {
		return "unknown origin"
	}
	return u.Scheme + "://" + u.Host
}

func refuseCredentialRedirect(req *http.Request, via []*http.Request) error {
	from := "unknown origin"
	if len(via) > 0 {
		from = originOf(via[0].URL)
	}
	return &refusedRedirect{from: from, to: originOf(req.URL)}
}

type cappedOutput struct {
	buf      bytes.Buffer
	max      int
	overflow bool
}

func (w *cappedOutput) Write(p []byte) (int, error) {
	if w.buf.Len()+len(p) > w.max {
		w.overflow = true
		return len(p), nil
	}
	return w.buf.Write(p)
}
