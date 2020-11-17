package store

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"cloud.google.com/go/storage"
	"google.golang.org/api/googleapi"
	"google.golang.org/api/option"
)

var bucketName string

func init() {
	bucketName = os.Getenv("BUCKET_NAME")
}

func fetchHeader(req *http.Request, key string) (string, bool) {
	if _, ok := req.Header[key]; ok {
		return req.Header.Get(key), true
	}
	return "", false
}

func bail(w http.ResponseWriter, err error) {
	fmt.Printf("%v\n", err)
	if apiErr, ok := err.(*googleapi.Error); ok {
		http.Error(w, err.Error(), apiErr.Code)
		return
	}
	http.Error(w, err.Error(), http.StatusBadGateway)
}

type Payload struct {
	Audience  string `json:"aud,omitempty"`
	ExpiresAt int64  `json:"exp,omitempty"`
	Id        string `json:"jti,omitempty"`
	IssuedAt  int64  `json:"iat,omitempty"`
	Issuer    string `json:"iss,omitempty"`
	NotBefore int64  `json:"nbf,omitempty"`
	Subject   string `json:"sub,omitempty"`

	// Non-Standard
	Email         string `json:"email,omitempty"`
	EmailVerified bool   `json:"email_verified,omitempty"`
}

type Header struct {
	Algorithm string `json:"alg,omitempty"`
	KeyID     string `json:"kid,omitempty"`
	Type      string `json:"typ,omitempty"`
}

type JWT struct {
	header  Header
	payload Payload
}

func decodeSegment(seg string) ([]byte, error) {
	if l := len(seg) % 4; l > 0 {
		seg += strings.Repeat("=", 4-l)
	}

	return base64.URLEncoding.DecodeString(seg)
}

func decode(jwt string) (*JWT, error) {
	split := strings.Split(jwt, ".")
	if len(split) != 3 {
		return nil, errors.New("malformed JWT")
	}

	headerJson, err := decodeSegment(split[0])
	if err != nil {
		return nil, err
	}

	payloadJson, err := decodeSegment(split[1])
	if err != nil {
		return nil, err
	}

	var header Header
	json.Unmarshal(headerJson, &header)

	var payload Payload
	json.Unmarshal(payloadJson, &payload)

	return &JWT{
		header:  header,
		payload: payload,
	}, nil
}

func Store(w http.ResponseWriter, req *http.Request) {
	// https://issuetracker.google.com/issues/173522140
	username, password, ok := req.BasicAuth()
	if !ok || username != "token" {
		w.WriteHeader(http.StatusForbidden)
		fmt.Printf("basic auth: username='%s', ok=%t\n", username, ok)
		return
	}

	jwt, err := decode(password)
	if err != nil {
		bail(w, err)
		return
	}

	fmt.Printf("jwt payload (signature not verified): %+v\n", jwt.payload)

	ctx := req.Context()
	client, err := storage.NewClient(ctx, option.WithAPIKey(password))
	if err != nil {
		bail(w, err)
		return
	}
	bucket := client.Bucket(bucketName)
	objectPath := req.URL.Path[1:]

	fmt.Printf("object path: %s", objectPath)

	object := bucket.Object(objectPath)

	switch req.Method {
	case http.MethodHead:
		_, err := object.Attrs(ctx)
		if err != nil {
			if err == storage.ErrObjectNotExist {
				http.Error(w, "File not found", http.StatusNotFound)
			} else {
				bail(w, err)
			}
			return
		}
	case http.MethodGet:
		rc, err := object.NewReader(ctx)
		if err != nil {
			if err == storage.ErrObjectNotExist {
				http.Error(w, "File not found", http.StatusNotFound)
			} else {
				bail(w, err)
			}
			return
		}
		defer rc.Close()
		io.Copy(w, rc)
	case http.MethodPut:
		// Write the object to GCS
		wc := object.NewWriter(ctx)

		// Copy the supported headers over from the original request
		if val, ok := fetchHeader(req, "Content-Type"); ok {
			wc.ContentType = val
		}
		if val, ok := fetchHeader(req, "Content-Language"); ok {
			wc.ContentLanguage = val
		}
		if val, ok := fetchHeader(req, "Content-Encoding"); ok {
			wc.ContentEncoding = val
		}
		if val, ok := fetchHeader(req, "Content-Disposition"); ok {
			wc.ContentDisposition = val
		}
		if val, ok := fetchHeader(req, "Cache-Control"); ok {
			wc.CacheControl = val
		}
		if _, err := io.Copy(wc, req.Body); err != nil {
			bail(w, err)
			return
		}
		if err := wc.Close(); err != nil {
			bail(w, err)
			return
		}
		fmt.Fprintf(w, "OK")
	default:
		msg := fmt.Sprintf("Method '%s' is not supported", req.Method)
		http.Error(w, msg, http.StatusMethodNotAllowed)
	}
}
