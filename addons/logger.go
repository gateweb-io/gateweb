package addons

import (
	"gateweb/libs/proxy/proxy"
	"fmt"
	"time"
)

type LoggerAddon struct {
	proxy.BaseAddon
}

func (l LoggerAddon) Request(flow *proxy.Flow) {
	fmt.Printf("[%s] --> %s %s%s\n",
		time.Now().Format("15:04:05"),
		flow.Request.Method,
		flow.Request.URL.Host,
		flow.Request.URL.Path,
	)
}

func (l LoggerAddon) Response(flow *proxy.Flow) {
	fmt.Printf("[%s] <-- %d %s%s\n",
		time.Now().Format("15:04:05"),
		flow.Response.StatusCode,
		flow.Request.URL.Host,
		flow.Request.URL.Path,
	)
}
