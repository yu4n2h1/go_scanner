package honeypot_ident

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"
)

type glastopf_finger struct {
	payload string
	finger  []string
}

var finger_data []glastopf_finger = []glastopf_finger{
	{"?../etc/passwd", []string{"root"}},
	{"?../etc/shadow", []string{"root"}},
	{"?../etc/group", []string{"root", "daemon"}},
	{"?../etc/hosts", []string{"127.0.0.1"}},
	{"", []string{"<h2>Blog Comments</h2>", "perlshop.cgi", "info.php", "Footer Powered By", "This is a really great entry"}},
	{"?../etc/services", []string{"exec", "root", "shell", "login"}},
}

func DetectGlastopf(ip string, port int) bool {
	var err error
	var response string
	var score, unscore int = 0, 0
	for _, finger := range finger_data {
		response, err = Get_request_text(ip, port, *&finger.payload)
		if err != nil {
			panic(err)
		}
		for idx := range *&finger.finger {
			if strings.Contains(response, *&finger.finger[idx]) {
				score += 1
				break
			}
		}
		if strings.Contains(response, ".:/usr/share/pear:/usr/share/php") {
			unscore += 1
		}
	}
	if unscore > 1 && score > 1 {
		return true
	}
	return false
}

func Get_request_text(ip string, port int, payload string) (string, error) {
	var url string = fmt.Sprintf("http://%s:%d/"+payload, ip, port)
	client := http.Client{
		Timeout: 3 * time.Second,
	}
	resp, err := client.Get(url)
	if err != nil {
		url = fmt.Sprintf("https://%s:%d/"+payload, ip, port)
		resp, err = client.Get(url)
		if err != nil {
			panic(err)
		}
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("Failed to read the website body: %w", err)
	}
	var bodystring string = string(body)
	return bodystring, nil
}
