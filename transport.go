package simple

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// HTTPResponse is the transport-neutral result of one HTTP exchange.
// Header keys are lowercase.
type HTTPResponse struct {
	StatusCode int
	Body       string
	Headers    map[string]string
	Err        error
}

// OK reports a transport-level success with a 2xx status.
func (r HTTPResponse) OK() bool {
	return r.Err == nil && r.StatusCode >= 200 && r.StatusCode < 300
}

// Header returns a header value case-insensitively, or "" when absent.
func (r HTTPResponse) Header(name string) string {
	return r.Headers[strings.ToLower(name)]
}

// HTTPClient abstracts the POST operation the protocol uses. Inject a fake
// in tests.
type HTTPClient interface {
	PostForm(ctx context.Context, rawURL string, fields url.Values) HTTPResponse
}

// DefaultHTTPClient performs real requests with net/http.
type DefaultHTTPClient struct {
	HTTP  *http.Client
	Agent string
}

// NewDefaultHTTPClient builds a DefaultHTTPClient with the given timeout and
// user agent.
func NewDefaultHTTPClient(timeout time.Duration, userAgent string) *DefaultHTTPClient {
	return &DefaultHTTPClient{
		HTTP: &http.Client{Timeout: timeout, CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		}},
		Agent: userAgent,
	}
}

// PostForm sends a form-urlencoded POST.
func (d *DefaultHTTPClient) PostForm(ctx context.Context, rawURL string, fields url.Values) HTTPResponse {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rawURL, strings.NewReader(fields.Encode()))
	if err != nil {
		return HTTPResponse{Err: err}
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if d.Agent != "" {
		req.Header.Set("User-Agent", d.Agent)
	}
	resp, err := d.HTTP.Do(req)
	if err != nil {
		return HTTPResponse{Err: err}
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024+1))
	if err != nil {
		return HTTPResponse{StatusCode: resp.StatusCode, Err: err}
	}
	if len(body) > 1024*1024 {
		return HTTPResponse{StatusCode: resp.StatusCode, Err: io.ErrUnexpectedEOF}
	}
	headers := make(map[string]string, len(resp.Header))
	for name, values := range resp.Header {
		if len(values) > 0 {
			headers[strings.ToLower(name)] = values[0]
		}
	}
	return HTTPResponse{StatusCode: resp.StatusCode, Body: string(body), Headers: headers}
}

var _ HTTPClient = (*DefaultHTTPClient)(nil)

func itoa(value int) string { return strconv.Itoa(value) }
