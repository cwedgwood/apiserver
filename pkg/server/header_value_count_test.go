/*
Copyright The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package server

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"k8s.io/apiserver/pkg/server/dynamiccertificates"
	certutil "k8s.io/client-go/util/cert"
)

func TestSetMaxHeaderValueCount(t *testing.T) {
	newServer := func() *http.Server {
		return &http.Server{MaxHeaderBytes: 1 << 20, ReadHeaderTimeout: time.Second}
	}
	server := newServer()
	setMaxHeaderValueCount(server)
	want := newServer()
	if field := reflect.ValueOf(want).Elem().FieldByName("MaxHeaderValueCount"); field.IsValid() {
		field.SetInt(8192)
	}
	if !reflect.DeepEqual(server, want) {
		t.Fatalf("server = %+v, want %+v", server, want)
	}
}

func TestServingIdentityHeaders(t *testing.T) {
	certPEM, keyPEM, err := certutil.GenerateSelfSignedCertKey("localhost", []net.IP{net.ParseIP("127.0.0.1")}, nil)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := dynamiccertificates.NewStaticCertKeyContent("serving-cert", certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certPEM) {
		t.Fatal("failed to add serving certificate to trust roots")
	}
	_, hasCountLimit := reflect.TypeOf(http.Server{}).FieldByName("MaxHeaderValueCount")

	for _, tc := range []struct {
		name     string
		secure   bool
		http2    bool
		protocol int
	}{
		{name: "secure-HTTP1", secure: true, protocol: 1},
		{name: "secure-HTTP2", secure: true, http2: true, protocol: 2},
		{name: "insecure-HTTP1", protocol: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			stopCh := make(chan struct{})
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("X-Received-Group-Count", fmt.Sprint(len(r.Header.Values("X-Remote-Group"))))
				w.WriteHeader(http.StatusOK)
			})
			scheme := "http"
			if tc.secure {
				scheme = "https"
				serving := &SecureServingInfo{Listener: listener, Cert: cert, DisableHTTP2: !tc.http2}
				stoppedCh, listenerStoppedCh, err := serving.Serve(handler, 5*time.Second, stopCh)
				if err != nil {
					listener.Close()
					t.Fatal(err)
				}
				t.Cleanup(func() {
					close(stopCh)
					<-listenerStoppedCh
					<-stoppedCh
				})
			} else {
				serving := &DeprecatedInsecureServingInfo{Listener: listener}
				if err := serving.Serve(handler, 5*time.Second, stopCh); err != nil {
					listener.Close()
					t.Fatal(err)
				}
				t.Cleanup(func() { close(stopCh) })
			}
			transport := &http.Transport{
				TLSClientConfig:   &tls.Config{RootCAs: roots},
				ForceAttemptHTTP2: tc.http2,
			}
			defer transport.CloseIdleConnections()
			client := &http.Client{Transport: transport, Timeout: 10 * time.Second}
			for _, count := range []int{1000, 8193} {
				req, err := http.NewRequest(http.MethodGet, scheme+"://"+listener.Addr().String(), nil)
				if err != nil {
					t.Fatal(err)
				}
				for i := range count {
					req.Header.Add("X-Remote-Group", fmt.Sprintf("group-%d", i))
				}
				resp, err := client.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				resp.Body.Close()
				wantStatus := []int{http.StatusOK}
				if hasCountLimit && count > 8192 {
					if tc.http2 {
						// Older golang.org/x/net HTTP/2 servers do not count header values;
						// newer ones apply MaxHeaderValueCount as net/http does.
						wantStatus = append(wantStatus, http.StatusRequestHeaderFieldsTooLarge)
					} else {
						wantStatus = []int{http.StatusRequestHeaderFieldsTooLarge}
					}
				}
				if resp.ProtoMajor != tc.protocol || !slices.Contains(wantStatus, resp.StatusCode) {
					t.Errorf("%d values: status/protocol = %d/%s, want one of %v/HTTP%d", count, resp.StatusCode, resp.Proto, wantStatus, tc.protocol)
				}
				if resp.StatusCode == http.StatusOK && resp.Header.Get("X-Received-Group-Count") != fmt.Sprint(count) {
					t.Errorf("handler received %q group values, want %d", resp.Header.Get("X-Received-Group-Count"), count)
				}
			}
			if !tc.http2 {
				req, err := http.NewRequest(http.MethodGet, scheme+"://"+listener.Addr().String(), nil)
				if err != nil {
					t.Fatal(err)
				}
				req.Header.Set("X-Remote-Group", strings.Repeat("x", (1<<20)+8192))
				resp, err := client.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				resp.Body.Close()
				if resp.StatusCode != http.StatusRequestHeaderFieldsTooLarge {
					t.Errorf("oversized header: status = %d, want 431", resp.StatusCode)
				}
			}
		})
	}
}
