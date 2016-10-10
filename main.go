package main

import (
	"encoding/json"
	"flag"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"./oauthsso"
	"path/filepath"
)

func main() {
	config := loadConfig()
	log.Printf("running on addr %s\n", config.Addr)
	http.Handle("/", oauthsso.NewServer(&config.Config))
	err := http.ListenAndServe(config.Addr, nil)
	log.Printf("%s\n", err.Error())
}

type Config struct {
	oauthsso.Config
	Addr            string
}

func loadConfig() Config {
	var configFile string
	pwd, err := filepath.Abs(filepath.Dir(os.Args[0]))
	if err != nil {
		log.Fatal(err)
	}
	flag.StringVar(&configFile, "c", pwd+"/config.json", "config file")
	flag.Parse()
	bytes, err := ioutil.ReadFile(configFile)
	if err != nil {
		log.Fatal(err)
	}
	config := Config{}
	err = json.Unmarshal(bytes, &config)
	if err != nil {
		log.Fatal("load config json unmarshal error ", err)
	}
	return config
}
