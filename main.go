package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
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
	targetHost := fmt.Sprintf("%s.%s%s.aliyuncs.com", bucket, region, internalSuffix)
	targetURL := fmt.Sprintf("%s://%s/%s", scheme, targetHost, objectName)

	log.Printf("Proxying %s %s", r.Method, targetURL)

	req, err := http.NewRequest(r.Method, targetURL, r.Body)
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

	contentType := req.Header.Get("Content-Type")
	contentMD5 := req.Header.Get("Content-MD5")
	if contentType == "" {
		contentType = "application/octet-stream"
	}

	signOSSRequest(req, bucket, objectName, contentType, contentMD5)

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

func signOSSRequest(req *http.Request, bucket, objectName, contentType, contentMD5 string) {
	date := time.Now().UTC().Format(http.TimeFormat)

	canonicalizedOSSHeaders := ""
	canonicalizedResource := fmt.Sprintf("/%s/%s", bucket, objectName)

	stringToSign := fmt.Sprintf("%s\n%s\n%s\n%s\n%s%s",
		req.Method,
		contentMD5,
		contentType,
		date,
		canonicalizedOSSHeaders,
		canonicalizedResource,
	)

	mac := hmac.New(sha1.New, []byte(secretKey))
	mac.Write([]byte(stringToSign))
	signature := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	authHeader := fmt.Sprintf("OSS %s:%s", accessKey, signature)

	req.Header.Set("Authorization", authHeader)
	req.Header.Set("Date", date)
	req.Header.Set("Content-Type", contentType)
	if contentMD5 != "" {
		req.Header.Set("Content-MD5", contentMD5)
	}
}
