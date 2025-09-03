package main

import (
	"github.com/renatogalera/openport-exporter/cmd"
	"log"
)

func main() {
	if err := cmd.Execute(); err != nil {
		log.Fatal(err)
	}
}
