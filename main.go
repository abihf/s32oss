package main

import (
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

func main() {
	if accessKey == "" || secretKey == "" {
		log.Fatal("Set OSS_ACCESS_KEY and OSS_SECRET_KEY environment variables first")
	}

	http.HandleFunc("/", handleProxy)
	log.Printf("OSS proxy (HMAC SigV4) listening on :9000 for region %s", region)
	log.Fatal(http.ListenAndServe(":9000", nil))
}

func handleProxy(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/health" {
		w.Write([]byte("ok"))
		return
	}

	// /bucket/object
	parts := strings.SplitN(strings.TrimPrefix(r.URL.Path, "/"), "/", 2)
	if len(parts) < 1 || parts[0] == "" {
		http.Error(w, "missing bucket", http.StatusBadRequest)
		return
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

	log.Printf("Proxying %s %s", r.Method, targetURL)

	// Stream r.Body directly to OSS without buffering into memory
	req, err := http.NewRequestWithContext(r.Context(), r.Method, targetURL, r.Body)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
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
		http.Error(w, err.Error(), 500)
		return
	}

	// Forward the request to AliCloud OSS
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		http.Error(w, err.Error(), 502)
		return
	}
	defer resp.Body.Close()

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

	// Use UNSIGNED-PAYLOAD to bypass the need to buffer the file into RAM for hashing
	payloadHash := "UNSIGNED-PAYLOAD"

	// If GitLab is doing a large chunked upload, we must use the streaming AWS constant
	if req.Header.Get("Content-Encoding") == "aws-chunked" {
		payloadHash = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD"
	}

	req.Header.Set("X-Amz-Content-Sha256", payloadHash)

	return signer.SignHTTP(
		req.Context(),
		creds,
		req,
		payloadHash,
		"s3",
		region,
		time.Now(),
	)
}
