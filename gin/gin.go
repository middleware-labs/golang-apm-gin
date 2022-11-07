package gin

import (
	"github.com/gin-gonic/gin"
	"github.com/middleware-labs/golang-apm/tracker"
	"go.opentelemetry.io/contrib/instrumentation/github.com/gin-gonic/gin/otelgin"
)

func Middleware(config *tracker.Config) gin.HandlerFunc {
	return otelgin.Middleware(config.ServiceName)
}
