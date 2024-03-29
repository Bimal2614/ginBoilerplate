package endpoints

import (
	"github.com/bimal2614/ginBoilerplate/src/controllers"
	"github.com/gin-gonic/gin"
)

func SetupWebsocketRoutes(router *gin.Engine) {
	router.GET("/ws", controllers.Websocket)
}
