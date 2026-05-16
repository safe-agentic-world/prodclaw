package normalize

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

type HTTPParams struct {
	Method         string            `json:"method"`
	Body           string            `json:"body"`
	Headers        map[string]string `json:"headers"`
	OutputMaxBytes int               `json:"output_max_bytes,omitempty"`
	OutputMaxLines int               `json:"output_max_lines,omitempty"`
}

func NormalizeHTTPParams(raw []byte) ([]byte, error) {
	var params HTTPParams
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&params); err != nil {
		return nil, fmt.Errorf("invalid http params: %w", err)
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return nil, errors.New("invalid http params: trailing data")
	}
	params.Method = strings.ToUpper(strings.TrimSpace(params.Method))
	if params.Method == "" {
		params.Method = http.MethodGet
	}
	if params.OutputMaxBytes < 0 || params.OutputMaxLines < 0 {
		return nil, errors.New("invalid http params: output caps must be >= 0")
	}
	if params.Headers == nil {
		params.Headers = map[string]string{}
	}
	canonicalHeaders := make(map[string]string, len(params.Headers))
	for key, value := range params.Headers {
		key = http.CanonicalHeaderKey(strings.TrimSpace(key))
		if key == "" {
			return nil, errors.New("invalid http params: header name is required")
		}
		canonicalHeaders[key] = value
	}
	params.Headers = canonicalHeaders
	encoded, err := json.Marshal(params)
	if err != nil {
		return nil, err
	}
	return encoded, nil
}

func NormalizeHTTPRequestTarget(raw string) (string, string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", "", errors.New("http url is required")
	}
	parsed, err := url.Parse(trimmed)
	if err != nil {
		return "", "", fmt.Errorf("invalid http url: %w", err)
	}
	switch strings.ToLower(parsed.Scheme) {
	case "url":
		if parsed.User != nil {
			return "", "", errors.New("url userinfo is not allowed")
		}
		resource, err := NormalizeResource(trimmed)
		if err != nil {
			return "", "", err
		}
		parsed.Scheme = "https"
		return resource, parsed.String(), nil
	case "http", "https":
		resource, err := NormalizeRedirectURL(trimmed)
		if err != nil {
			return "", "", err
		}
		return resource, parsed.String(), nil
	default:
		return "", "", errors.New("http url scheme must be http, https, or url")
	}
}
