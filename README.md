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
	r := gin.Default()
	config, _ := track.Track(
		track.WithConfigTag("service", "your service name"),
		track.WithConfigTag("projectName", "your project name"),
	)
	r.Use(g.Middleware(config))
	r.GET("/books", FindBooks)
	r.Run(":8090")
}

func FindBooks(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"data": "ok"})
}