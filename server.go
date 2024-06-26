// go get gopkg.in/yaml.v2
// go run server.go -config config.yaml -test

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	// "os"
	"os/exec"
	"strings"
	"sync"
	"time"
	"gopkg.in/yaml.v2"
)

type App struct {
	Port        int    `yaml:"port"`
	AccessKey   string `yaml:"access_key"`
	Destination string `yaml:"destination"`
	Duration    int    `yaml:"duration"`
}

var (
	configFile  string
	testMode    bool
	config      map[string]App
	sessions    []Session
	lock        sync.Mutex
	sessionFile = "session_cache.json"
)

type Session struct {
	IptablesCommand string
	ExpiresAt       time.Time
}

func main() {
	flag.StringVar(&configFile, "config", "config.yaml", "Path to configuration file")
	flag.BoolVar(&testMode, "test", false, "Enable test mode to mock iptables commands")
	flag.Parse()

	log.Println("Loading configuration...")
	config = loadConfig(configFile)
	log.Println("Configuration loaded successfully.")

	http.HandleFunc("/", handleRequest)
	log.Println("Server is starting on port 8080...")
	go manageSessions()
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func loadConfig(configPath string) map[string]App {
	var c map[string]App
	yamlFile, err := ioutil.ReadFile(configPath)
	if err != nil {
		log.Fatalf("Error reading YAML file: %s\n", err)
	}
	err = yaml.Unmarshal(yamlFile, &c)
	if err != nil {
		log.Fatalf("Error parsing YAML file: %s\n", err)
	}
	return c
}

func manageSessions() {
    file, err := ioutil.ReadFile(sessionFile)
    if err != nil {
        log.Printf("No existing session file found or error reading: %s. Starting fresh.\n", err)
        sessions = []Session{} // Initialize empty if no file found
        return
    }
    if err = json.Unmarshal(file, &sessions); err != nil {
        log.Printf("Error parsing session file: %s. Starting fresh.\n", err)
        sessions = []Session{} // Initialize empty if error parsing
    }

	for {
		time.Sleep(5 * time.Second)
		currentTime := time.Now()
		lock.Lock()
		var activeSessions []Session
		for _, session := range sessions {
			if currentTime.Before(session.ExpiresAt) {
				activeSessions = append(activeSessions, session)
			} else {
				if testMode {
					log.Printf("Mock command: %s\n", strings.Replace(session.IptablesCommand, "-A", "-D", 1))
				} else {
					executeCommand(strings.Replace(session.IptablesCommand, "-A", "-D", 1))
				}
			}
		}
		sessions = activeSessions
		file, _ := json.MarshalIndent(sessions, "", " ")
		_ = ioutil.WriteFile(sessionFile, file, 0644)
		lock.Unlock()
	}
}

func handleRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		// http.Error(w, "Invalid request method.", 405)
		http.Error(w, "", 503)
		log.Println("Received non-POST request")
		return
	}
	if err := r.ParseForm(); err != nil {
		// http.Error(w, "Error parsing form data.", 400)
		http.Error(w, "", 503)
		log.Println("Error parsing form data")
		return
	}
	appName := r.PostFormValue("app")
	accessKey := r.PostFormValue("access_key")
	log.Printf("Parsed form data - App: %s, Access Key: %s\n", appName, accessKey)

	if app, exists := config[appName]; exists && app.AccessKey == accessKey {
		clientIP := strings.Split(r.RemoteAddr, ":")[0]
		var iptablesCommand string
		if app.Destination == "local" {
			iptablesCommand = fmt.Sprintf("iptables -A INPUT -s %s -p tcp --dport %d -j ACCEPT", clientIP, app.Port)
		} else {
			ipPort := strings.Split(app.Destination, ":")
			iptablesCommand = fmt.Sprintf("iptables -A FORWARD -s %s -d %s --dport %s -j ACCEPT", clientIP, ipPort[0], ipPort[1])
		}
		if testMode {
			log.Printf("Mock command: %s\n", iptablesCommand)
		} else {
			executeCommand(iptablesCommand)
		}
		lock.Lock()
		sessions = append(sessions, Session{IptablesCommand: iptablesCommand, ExpiresAt: time.Now().Add(time.Duration(app.Duration) * time.Second)})
		lock.Unlock()
		// http.Error(w, "Access Granted", 200)
		http.Error(w, "", 503)
	} else {
		log.Printf("Unauthorized access attempt or invalid app credentials for App: %s, Access Key: %s\n", appName, accessKey)
		// http.Error(w, "Unauthorized", 403)
		http.Error(w, "", 503)
	}
}

func executeCommand(command string) {
	log.Printf("Executing command: %s\n", command)
	cmd := exec.Command("sh", "-c", command)
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("Error executing command: %s, Output: %s\n", err, string(output))
	} else {
		log.Printf("Command output: %s\n", string(output))
	}
}
