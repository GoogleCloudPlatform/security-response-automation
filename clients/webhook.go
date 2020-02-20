package clients

// Copyright 2019 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import (
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
)

// WebhookClient client provider
type WebhookClient interface {
	Send(url, contentType string, body io.Reader) (*http.Response, error)
}

// Webhook client
type Webhook struct {
	Service http.Client
}

// NewWebhookClient returns and initializes the HTTP client
func NewWebhookClient() *Webhook {
	return &Webhook{Service: http.Client{}}
}

// Send sends a request to a url
func Send(url, contentType string, body io.Reader) (*http.Response, error) {
	var (
		err      error
		response *http.Response
		retries  int = 3
	)
	for retries > 0 {
		response, err = http.Post(url, contentType, body)
		if err != nil {
			log.Println(err)
			retries--
		} else {
			break
		}
	}
	if response != nil {
		defer response.Body.Close()
		data, err := ioutil.ReadAll(response.Body)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("data = %s\n", data)
	}

	return response, err
}
