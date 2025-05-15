package hunter

import (
	"context"
	"encoding/base64"
	"fmt"
	"time"

	jsoniter "github.com/json-iterator/go"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

// hunter API 返回的响应结构体
type hunterResp struct {
	Code    int        `json:"code"`    // 状态码，200为成功，401/400为key错误或无权限
	Data    hunterData `json:"data"`    // 结果数据
	Message string     `json:"message"` // 错误信息或提示
}

// 单条子域名信息结构体
type infoArr struct {
	URL      string `json:"url"`
	IP       string `json:"ip"`
	Port     int    `json:"port"`
	Domain   string `json:"domain"`
	Protocol string `json:"protocol"`
}

// hunter API 返回的 data 字段结构体
type hunterData struct {
	InfoArr []infoArr `json:"arr"`   // 子域名信息数组
	Total   int       `json:"total"` // 总数量
}

// Source 代表 hunter 被动子域名数据源
type Source struct {
	apiKeys   []string      // 存储所有可用的 API Key
	timeTaken time.Duration // 本次查询耗时
	errors    int           // 错误次数
	results   int           // 结果数量
	skipped   bool          // 是否跳过（如无key等情况）
}

// Run 是 subfinder 的核心接口，执行子域名查询
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
		// 顺序遍历所有 key
		for keyIdx, apiKey := range s.apiKeys {
			var pages = 1
			var queryErr error
			for currentPage := 1; currentPage <= pages; currentPage++ {
				qbase64 := base64.URLEncoding.EncodeToString([]byte(fmt.Sprintf("domain=\"%s\"", domain)))
				resp, err := session.SimpleGet(ctx, fmt.Sprintf(
					"https://hunter.qianxin.com/openApi/search?api-key=%s&search=%s&page=1&page_size=100&is_web=3",
					apiKey, qbase64))
				if err != nil && resp == nil {
					queryErr = err
					s.errors++
					session.DiscardHTTPResponse(resp)
					break // 当前key失败，尝试下一个key
				}

				var response hunterResp
				err = jsoniter.NewDecoder(resp.Body).Decode(&response)
				resp.Body.Close()
				if err != nil {
					queryErr = err
					s.errors++
					break // 当前key失败，尝试下一个key
				}

				if response.Code == 401 || response.Code == 400 {
					queryErr = fmt.Errorf("%s", response.Message)
					s.errors++
					break // 当前key失败，尝试下一个key
				}

				if response.Data.Total > 0 {
					for _, hunterInfo := range response.Data.InfoArr {
						success = true
						s.results++
						subdomain := hunterInfo.Domain
						results <- subscraping.Result{Source: s.Name(), Type: subscraping.Subdomain, Value: subdomain}
					}
				}
				pages = int(response.Data.Total/1000) + 1
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

// Name 返回数据源名称
func (s *Source) Name() string {
	return "hunter"
}

// IsDefault 是否为默认启用的数据源
func (s *Source) IsDefault() bool {
	return true
}

// HasRecursiveSupport 是否支持递归查询
func (s *Source) HasRecursiveSupport() bool {
	return false
}

// NeedsKey 是否需要 API Key
func (s *Source) NeedsKey() bool {
	return true
}

// AddApiKeys 添加 API Key（支持多个）
func (s *Source) AddApiKeys(keys []string) {
	s.apiKeys = keys
}

// Statistics 返回本次查询的统计信息
func (s *Source) Statistics() subscraping.Statistics {
	return subscraping.Statistics{
		Errors:    s.errors,
		Results:   s.results,
		TimeTaken: s.timeTaken,
		Skipped:   s.skipped,
	}
}
