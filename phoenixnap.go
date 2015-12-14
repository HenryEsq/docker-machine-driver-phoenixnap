package main

import (
	"github.com/allingeek/docker-machine-driver-phoenixnap/driver"
	"github.com/docker/machine/libmachine/drivers/plugin"
)

func main() {
	plugin.RegisterDriver(driver.NewDriver("", ""))
}
