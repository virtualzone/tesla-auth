package main

import (
	"log"
	"os"
	"strconv"
	"sync"
)

type Config struct {
	Hostname          string
	Port              int
	TeslaClientID     string
	TeslaClientSecret string
	TeslaAudience     string
	PublicKeyPath     string
}

var _configInstance *Config
var _configOnce sync.Once

func GetConfig() *Config {
	_configOnce.Do(func() {
		_configInstance = &Config{}
		_configInstance.ReadConfig()
	})
	return _configInstance
}

func (c *Config) ReadConfig() {
	c.Hostname = c.getEnv("HOSTNAME", "localhost:8080")
	port, err := strconv.Atoi(c.getEnv("PORT", "8080"))
	if err != nil {
		log.Panicln("PORT must be numeric")
	}
	c.Port = port
	c.TeslaClientID = c.getEnv("TESLA_CLIENT_ID", "")
	c.TeslaClientSecret = c.getEnv("TESLA_CLIENT_SECRET", "")
	c.TeslaAudience = c.getEnv("TESLA_AUDIENCE", "https://fleet-api.prd.eu.vn.cloud.tesla.com")
	c.PublicKeyPath = c.getEnv("PUBLIC_KEY_PATH", "")
}

func (c *Config) getEnv(key, defaultValue string) string {
	res := os.Getenv(key)
	if res == "" {
		return defaultValue
	}
	return res
}
