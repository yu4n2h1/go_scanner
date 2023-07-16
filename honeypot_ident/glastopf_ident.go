package honeypot_ident

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
)

func DetectGlastopf(ip string, port int) bool {
	var err error
	var score int = 0
	var response string
	var reserror string = ".:/usr/share/pear:/usr/share/php"
	var signs [4]string = [4]string{"perlshop.cgi", "info.php", "Footer Powered By", "This is a really great entry"}
	response, err = get_request_text(ip, port, "?../etc/passwd")
	if err != nil {
		panic(err)
	}
	if strings.Contains(response, reserror) || strings.Contains(response, "root") {
		score += 1
	}

	response, err = get_request_text(ip, port, "?../etc/shadow")
	if err != nil {
		panic(err)
	}
	if strings.Contains(response, reserror) || strings.Contains(response, "root") {
		score += 2
	}

	response, err = get_request_text(ip, port, "?../etc/group")
	if err != nil {
		panic(err)
	}
	if strings.Contains(response, reserror) || (strings.Contains(response, "root") || strings.Contains(response, "daemon")) {
		score += 1
	}

	response, err = get_request_text(ip, port, "")
	if err != nil {
		panic(err)
	}
	if strings.Contains(response, "<h2>Blog Comments</h2>") && strings.Contains(response, "Please post your comments for the blog") {
		score += 2
		fmt.Println("this glastopf isn't change")
	}
	for _, sign := range signs {
		if strings.Contains(response, sign) {
			score += 3
			break
		}
	}
	if score >= 3 {
		return true
	}
	return false
}

func get_request_text(ip string, port int, payload string) (string, error) {
	var url string = fmt.Sprintf("http://%s:%d/"+payload, ip, port)

	resp, err := http.Get(url)
	if err != nil {
		return "", fmt.Errorf("Failed to request the website: %w", err)
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("Failed to read the website body: %w", err)
	}
	var bodystring string = string(body)
	return bodystring, nil
}
