// Package quake logic
package quake

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"time"

	jsoniter "github.com/json-iterator/go"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

type quakeResults struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    []struct {
		Service struct {
			HTTP struct {
				Host string `json:"host"`
			} `json:"http"`
		}
	} `json:"data"`
	Meta struct {
		Pagination struct {
			Total int `json:"total"`
		} `json:"pagination"`
	} `json:"meta"`
}

// Source is the passive scraping agent
type Source struct {
	apiKeys   []string
	timeTaken time.Duration
	errors    int
	results   int
	skipped   bool
}

// Run function returns all subdomains found with the service
func (s *Source) Run(ctx context.Context, domain string, session *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result)
	s.errors = 0
	s.results = 0

	go func() {
		defer func(startTime time.Time) {
			s.timeTaken = time.Since(startTime)
			close(results)
		}(time.Now())

		if len(s.apiKeys) == 0 {
			s.skipped = true
			return
		}

		var success bool
		for keyIdx, apiKey := range s.apiKeys {
			var queryErr error
			// quake api doc https://quake.360.cn/quake/#/help
			requestBody := []byte(fmt.Sprintf(`{"query":"domain: %s", "include":["service.http.host"], "latest": true, "start":0, "size":500}`, domain))
			resp, err := session.Post(ctx, "https://quake.360.net/api/v3/search/quake_service", "", map[string]string{
				"Content-Type": "application/json", "X-QuakeToken": apiKey,
			}, bytes.NewReader(requestBody))
			if err != nil {
				queryErr = err
				s.errors++
				session.DiscardHTTPResponse(resp)
				continue // 当前key失败，尝试下一个key
			}

			var response quakeResults
			err = jsoniter.NewDecoder(resp.Body).Decode(&response)
			resp.Body.Close()
			if err != nil {
				queryErr = err
				s.errors++
				continue // 当前key失败，尝试下一个key
			}

			if response.Code != 0 {
				queryErr = fmt.Errorf("%s", response.Message)
				s.errors++
				continue // 当前key失败，尝试下一个key
			}

			if response.Meta.Pagination.Total > 0 {
				for _, quakeDomain := range response.Data {
					success = true
					s.results++
					subdomain := quakeDomain.Service.HTTP.Host
					if strings.ContainsAny(subdomain, "暂无权限") {
						subdomain = ""
					}
					results <- subscraping.Result{Source: s.Name(), Type: subscraping.Subdomain, Value: subdomain}
				}
			}
			if success {
				break // 有一个key成功就不再尝试后续key
			}
			if keyIdx == len(s.apiKeys)-1 && !success && queryErr != nil {
				// 所有key都失败，输出最后一次错误
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: queryErr}
			}
		}
		if !success {
			s.skipped = true
		}
	}()

	return results
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "quake"
}

func (s *Source) IsDefault() bool {
	return true
}

func (s *Source) HasRecursiveSupport() bool {
	return false
}

func (s *Source) NeedsKey() bool {
	return true
}

func (s *Source) AddApiKeys(keys []string) {
	s.apiKeys = keys
}

func (s *Source) Statistics() subscraping.Statistics {
	return subscraping.Statistics{
		Errors:    s.errors,
		Results:   s.results,
		TimeTaken: s.timeTaken,
		Skipped:   s.skipped,
	}
}
