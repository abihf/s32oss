package main

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsv4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
)

const (
	scheme = "https"
)

var (
	region    = os.Getenv("OSS_REGION")
	accessKey = os.Getenv("OSS_ACCESS_KEY")
	secretKey = os.Getenv("OSS_SECRET_KEY")

	useInternal = os.Getenv("OSS_USE_INTERNAL") == "true"

	// These headers are rejected by AliCloud OSS and will cause 500 errors during DeleteObjects
	ignoredReqHeaders = []string{
		"Authorization",
		"Date",
		"X-Amz-Checksum-Algorithm",
		"X-Amz-Sdk-Checksum-Algorithm",
		"X-Amz-Checksum-Crc32",
		"X-Amz-Checksum-Crc32c",
		"X-Amz-Checksum-Sha1",
		"X-Amz-Checksum-Sha256",
	}
)

type HttpError struct {
	error
	status int
}

func main() {
	if accessKey == "" || secretKey == "" {
		log.Fatal("Set OSS_ACCESS_KEY and OSS_SECRET_KEY environment variables first")
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		err := handleProxy(w, r)
		if err != nil {
			var httpErr *HttpError
			if ok := errors.As(err, &httpErr); ok {
				http.Error(w, httpErr.error.Error(), httpErr.status)
				return
			}
			http.Error(w, err.Error(), 500)
		}
	})
	log.Printf("OSS proxy (HMAC SigV4) listening on :9000 for region %s", region)
	log.Fatal(http.ListenAndServe(":9000", nil))
}

func handleProxy(w http.ResponseWriter, r *http.Request) error {
	if r.URL.Path == "/health" {
		w.Write([]byte("ok"))
		return nil
	}

	// /bucket/object
	parts := strings.SplitN(strings.TrimPrefix(r.URL.Path, "/"), "/", 2)
	if len(parts) < 1 || parts[0] == "" {
		return HttpError{error: errors.New("missing bucket"), status: http.StatusBadRequest}
	}
	bucket := parts[0]
	objectName := ""
	if len(parts) > 1 {
		objectName = parts[1]
	}

	internalSuffix := ""
	if useInternal {
		internalSuffix = "-internal"
	}
	query := ""
	if r.URL.RawQuery != "" {
		query = "?" + r.URL.RawQuery
	}

	targetHost := fmt.Sprintf("%s.%s%s.aliyuncs.com", bucket, region, internalSuffix)
	targetURL := fmt.Sprintf("%s://%s/%s%s", scheme, targetHost, objectName, query)

	// Stream r.Body directly to OSS without buffering into memory
	req, err := http.NewRequestWithContext(r.Context(), r.Method, targetURL, r.Body)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Crucial for direct streaming: Explicitly set the content length
	req.ContentLength = r.ContentLength

	// Copy relevant headers, ignoring incompatible ones
	for k, v := range r.Header {
		ignored := false
		for _, name := range ignoredReqHeaders {
			if strings.EqualFold(k, name) {
				ignored = true
				break
			}
		}
		if ignored {
			continue
		}
		for _, vv := range v {
			req.Header.Add(k, vv)
		}
	}

	// Sign the request
	if err := signSigV4Request(req, region, accessKey, secretKey); err != nil {
		return fmt.Errorf("failed to sign request: %w", err)
	}

	// Forward the request to AliCloud OSS
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return HttpError{error: err, status: 502}
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		log.Printf("Request error %s %s %d", req.Method, req.URL.String(), resp.StatusCode)
	}

	// Apply HEAD request fixes for GitLab 19 AWS SDK v2 compatibility
	if req.Method == http.MethodHead && resp.StatusCode >= 200 && resp.StatusCode < 300 {
		quirkHeadHeader(&resp.Header)
	}

	// Proxy response back to GitLab
	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
	return nil
}

func quirkHeadHeader(headers *http.Header) {
	lm := headers.Get("Last-Modified")
	if lm == "" {
		// Prevent AWS SDK v2 nil pointer panic
		headers.Set("Last-Modified", time.Now().UTC().Format(http.TimeFormat))
	} else {
		// Ensure standard HTTP RFC1123 time format
		if t, err := time.Parse(time.RFC3339, lm); err == nil {
			headers.Set("Last-Modified", t.UTC().Format(http.TimeFormat))
		}
	}

	if headers.Get("Content-Length") == "" {
		headers.Set("Content-Length", "0")
	}
}

func signSigV4Request(req *http.Request, region, accessKey, secretKey string) error {
	creds := aws.Credentials{
		AccessKeyID:     accessKey,
		SecretAccessKey: secretKey,
		Source:          "manual",
	}

	signer := awsv4.NewSigner()

	// 1. Steal the payload hash already calculated by GitLab's AWS SDK!
	// This gives OSS the exact hash it wants without us needing to buffer the file into RAM.
	payloadHash := req.Header.Get("X-Amz-Content-Sha256")

	// 2. Fallback just in case it's missing (keeps chunked uploads working)
	if payloadHash == "" {
		payloadHash = "UNSIGNED-PAYLOAD"
		req.Header.Set("X-Amz-Content-Sha256", payloadHash)
	}

	return signer.SignHTTP(
		req.Context(),
		creds,
		req,
		payloadHash, // Pass the exact hash (or STREAMING constant) to the signer
		"s3",
		region,
		time.Now(),
	)
}
