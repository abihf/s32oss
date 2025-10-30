package main

import (
	"bytes"
	"crypto/sha256"
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
)

func main() {
	if accessKey == "" || secretKey == "" {
		log.Fatal("Set OSS_ACCESS_KEY and OSS_SECRET_KEY environment variables first")
	}

	http.HandleFunc("/", handleProxy)
	log.Printf("OSS proxy (HMAC-SHA1 signer) listening on :9000 for region %s", region)
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

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	r.Body.Close()

	log.Printf("Proxying %s %s", r.Method, targetURL)

	req, err := http.NewRequestWithContext(r.Context(), r.Method, targetURL, bytes.NewReader(body))
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	// Copy relevant headers
	for k, v := range r.Header {
		if strings.EqualFold(k, "Authorization") || strings.EqualFold(k, "Date") {
			continue
		}
		for _, vv := range v {
			req.Header.Add(k, vv)
		}
	}

	signSigV4Request(req, body, region, accessKey, secretKey)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		http.Error(w, err.Error(), 502)
		return
	}
	defer resp.Body.Close()

	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func signSigV4Request(req *http.Request, body []byte, region, accessKey, secretKey string) error {
	creds := aws.Credentials{
		AccessKeyID:     accessKey,
		SecretAccessKey: secretKey,
		Source:          "manual",
	}

	signer := awsv4.NewSigner()
	payloadHash := fmt.Sprintf("%x", sha256.Sum256(body))

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
