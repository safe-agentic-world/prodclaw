package executor

import (
	"context"
	"errors"
	"io"
	"net/http"
	neturl "net/url"
	"strings"

	"github.com/safe-agentic-world/prodclaw/internal/normalize"
)

const DefaultHTTPRequestMaxBytes = 64 * 1024

type HTTPParams struct {
	Method string            `json:"method"`
	Body   string            `json:"body"`
	Header map[string]string `json:"headers"`
}

type HTTPResult struct {
	StatusCode    int
	Body          string
	Truncated     bool
	FinalResource string
	RedirectHops  int
}

type RedirectPolicy struct {
	Enabled    bool
	HopLimit   int
	AllowHosts []string
}

type HTTPRunner struct {
	client *http.Client
}

var (
	ErrHTTPRequestTooLarge      = errors.New("http request body exceeds configured limit")
	ErrRedirectDenied           = errors.New("http redirects are not allowed")
	ErrRedirectHopLimit         = errors.New("http redirect hop limit exceeded")
	ErrRedirectDisallowedHost   = errors.New("http redirect destination is not allowlisted")
	ErrRedirectInvalidTarget    = errors.New("http redirect target is invalid")
	ErrHTTPRedirectAllowlistReq = errors.New("http redirects require an explicit host allowlist")
)

func NewHTTPRunner(client *http.Client) *HTTPRunner {
	if client == nil {
		client = &http.Client{}
	}
	return &HTTPRunner{client: client}
}

func (r *HTTPRunner) DoWithPolicy(ctx context.Context, rawURL string, params HTTPParams, policy RedirectPolicy, requestMaxBytes, responseMaxBytes int) (HTTPResult, error) {
	if requestMaxBytes <= 0 {
		requestMaxBytes = DefaultHTTPRequestMaxBytes
	}
	if len(params.Body) > requestMaxBytes {
		return HTTPResult{}, ErrHTTPRequestTooLarge
	}
	if responseMaxBytes <= 0 {
		responseMaxBytes = DefaultOutputMaxBytes
	}
	if policy.Enabled && len(policy.AllowHosts) == 0 {
		return HTTPResult{}, ErrHTTPRedirectAllowlistReq
	}

	currentURL, currentResource, err := resolveInitialTarget(rawURL)
	if err != nil {
		return HTTPResult{}, err
	}
	currentMethod := params.Method
	if currentMethod == "" {
		currentMethod = http.MethodGet
	}
	redirectHops := 0

	transport := r.client.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}

	for {
		req, err := newHTTPRequest(ctx, currentMethod, currentURL, params)
		if err != nil {
			return HTTPResult{}, err
		}
		resp, err := transport.RoundTrip(req)
		if err != nil {
			return HTTPResult{}, err
		}
		if !isRedirectResponse(resp.StatusCode) {
			defer func() { _ = resp.Body.Close() }()
			limited := io.LimitReader(resp.Body, int64(responseMaxBytes+1))
			body, err := io.ReadAll(limited)
			if err != nil {
				return HTTPResult{}, err
			}
			truncated := len(body) > responseMaxBytes
			if truncated {
				body = body[:responseMaxBytes]
			}
			return HTTPResult{
				StatusCode:    resp.StatusCode,
				Body:          string(body),
				Truncated:     truncated,
				FinalResource: currentResource,
				RedirectHops:  redirectHops,
			}, nil
		}
		if err := resp.Body.Close(); err != nil {
			return HTTPResult{}, err
		}
		location := strings.TrimSpace(resp.Header.Get("Location"))
		if location == "" {
			return HTTPResult{}, ErrRedirectInvalidTarget
		}
		currentURL, currentResource, currentMethod, err = nextRedirectTarget(currentURL, currentMethod, location, policy, redirectHops)
		if err != nil {
			return HTTPResult{}, err
		}
		redirectHops++
	}
}

func HTTPRequestLimit(obligations map[string]any) int {
	return effectiveLimit(DefaultHTTPRequestMaxBytes, obligationInt(obligations["http_request_max_bytes"]), 0)
}

func HTTPResponseLimit(obligations map[string]any, requestedMaxBytes int) int {
	return effectiveLimit(DefaultOutputMaxBytes, obligationInt(obligations["output_max_bytes"]), requestedMaxBytes)
}

func resolveInitialTarget(rawURL string) (*neturl.URL, string, error) {
	resource, actualURL, err := normalize.NormalizeHTTPRequestTarget(rawURL)
	if err != nil {
		return nil, "", ErrRedirectInvalidTarget
	}
	parsed, err := neturl.Parse(actualURL)
	if err != nil {
		return nil, "", ErrRedirectInvalidTarget
	}
	targetURL, err := executableURL(parsed)
	if err != nil {
		return nil, "", ErrRedirectInvalidTarget
	}
	return targetURL, resource, nil
}

func executableURL(parsed *neturl.URL) (*neturl.URL, error) {
	if parsed == nil {
		return nil, ErrRedirectInvalidTarget
	}
	if parsed.Scheme == "url" {
		parsed = cloneURL(parsed)
		parsed.Scheme = "https"
	}
	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "http" && scheme != "https" {
		return nil, ErrRedirectInvalidTarget
	}
	if parsed.User != nil || parsed.Host == "" {
		return nil, ErrRedirectInvalidTarget
	}
	return parsed, nil
}

func nextRedirectTarget(current *neturl.URL, method, location string, policy RedirectPolicy, redirectHops int) (*neturl.URL, string, string, error) {
	if !policy.Enabled {
		return nil, "", "", ErrRedirectDenied
	}
	limit := policy.HopLimit
	if limit <= 0 {
		limit = 3
	}
	if redirectHops+1 > limit {
		return nil, "", "", ErrRedirectHopLimit
	}
	parsedLocation, err := neturl.Parse(location)
	if err != nil {
		return nil, "", "", ErrRedirectInvalidTarget
	}
	resolved := current.ResolveReference(parsedLocation)
	resource, actualURL, err := normalize.NormalizeHTTPRequestTarget(resolved.String())
	if err != nil {
		return nil, "", "", ErrRedirectInvalidTarget
	}
	safeURL, err := neturl.Parse(actualURL)
	if err != nil {
		return nil, "", "", ErrRedirectInvalidTarget
	}
	host := hostFromNormalizedResource(resource)
	if !hostAllowlisted(policy.AllowHosts, host) {
		return nil, "", "", ErrRedirectDisallowedHost
	}
	return safeURL, resource, redirectMethod(method), nil
}

func newHTTPRequest(ctx context.Context, method string, target *neturl.URL, params HTTPParams) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, target.String(), strings.NewReader(params.Body))
	if err != nil {
		return nil, err
	}
	for key, value := range params.Header {
		req.Header.Set(key, value)
	}
	return req, nil
}

func hostAllowlisted(allowHosts []string, host string) bool {
	for _, allowed := range allowHosts {
		if strings.TrimSpace(allowed) == host {
			return true
		}
	}
	return false
}

func hostFromNormalizedResource(resource string) string {
	trimmed := strings.TrimPrefix(resource, "url://")
	if idx := strings.Index(trimmed, "/"); idx >= 0 {
		return trimmed[:idx]
	}
	return trimmed
}

func redirectMethod(method string) string {
	switch method {
	case http.MethodGet, http.MethodHead:
		return method
	default:
		return http.MethodGet
	}
}

func isRedirectResponse(statusCode int) bool {
	switch statusCode {
	case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther, http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
		return true
	default:
		return false
	}
}

func cloneURL(value *neturl.URL) *neturl.URL {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}
