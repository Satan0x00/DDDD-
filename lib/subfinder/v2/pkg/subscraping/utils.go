package subscraping

import (
	"math/rand"
	"strings"

	"github.com/projectdiscovery/gologger"
)

const MultipleKeyPartsLength = 2 // 多段key的分割长度（如 user:key）

// PickRandom 从传入的切片 v 中随机选取一个元素并返回
// 泛型 T 允许该函数适用于任意类型的切片
// v: 可选项（如API Key列表）
// sourceName: 数据源名称，用于日志输出
func PickRandom[T any](v []T, sourceName string) T {
	var result T
	length := len(v)
	if length == 0 {
		// 如果没有可用项，输出调试日志并返回零值
		gologger.Debug().Msgf("Cannot use the %s source because there was no API key/secret defined for it.", sourceName)
		return result
	}
	// 随机返回一个元素
	return v[rand.Intn(length)]
}

// CreateApiKeys 用于将字符串类型的key列表转换为结构体切片
// keys: 形如 ["user1:key1", "user2:key2"] 的字符串切片
// provider: 一个函数，接收分割后的两个字符串，返回目标类型T
// 返回值：T类型的切片（如apiKey结构体切片）
func CreateApiKeys[T any](keys []string, provider func(k, v string) T) []T {
	var result []T
	for _, key := range keys {
		// 尝试将key按冒号分割为两部分
		if keyPartA, keyPartB, ok := createMultiPartKey(key); ok {
			// 用provider函数生成目标类型并加入结果
			result = append(result, provider(keyPartA, keyPartB))
		}
	}
	return result
}

// createMultiPartKey 将字符串key按冒号分割为两部分
// 返回：key的前半部分、后半部分、是否分割成功
func createMultiPartKey(key string) (keyPartA, keyPartB string, ok bool) {
	parts := strings.Split(key, ":")
	ok = len(parts) == MultipleKeyPartsLength // 必须正好两段

	if ok {
		keyPartA = parts[0]
		keyPartB = parts[1]
	}

	return
}
