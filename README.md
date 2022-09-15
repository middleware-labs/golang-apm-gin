# golang-apm-gin

go get github.com/middleware-labs/golang-apm-gin


```golang

package main

import (
	"github.com/gin-gonic/gin"
	g "github.com/middleware-labs/golang-apm-gin/gin"
	track "github.com/middleware-labs/golang-apm/tracker"
	"net/http"
)

func main() {
	go track.Track(
		track.WithConfigTag("service", "service1"),
		track.WithConfigTag("host", "localhost:4320"),
		track.WithConfigTag("projectName", "demo-agent-apm"),
	)
	r := gin.Default()
	r.Use(g.Middleware("serviceName"))
	r.GET("/books", FindBooks)
	r.Run(":8090")
}

func FindBooks(c *gin.Context) {
	span := track.SpanFromContext(c.Request.Context())
	span.SetAttributes(track.String("controller", "books"))
	c.JSON(http.StatusOK, gin.H{"data": "ok"})
}