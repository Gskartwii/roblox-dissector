package peer

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/local/plib/phttp"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type RobloxSession struct {
	username, password, Cookie string
	Client                     *http.Client
}

func NewRobloxSession(username, password string) *RobloxSession {
	ts := http.Transport{IdleConnTimeout: time.Second * 30}
	client := http.Client{Transport: &ts}
	jar, _ := cookiejar.New(nil)
	client.Jar = jar

	return &RobloxSession{username: username, password: password, Client: &client}
}

// GetAuthTicket provides a ticket required for joining games in peer/Client.go
func GetAuthTicketWithCookie(cookie string, placeId uint64) (string, error) {
	client := http.Client{}
	req, _ := http.NewRequest("GET", "https://www.roblox.com/game-auth/getauthticket", nil)
	req.Header.Add("RBX-For-Gameauth", "true")
	req.Header.Add("Accept", "*/*")
	req.Header.Add("Cookie", fmt.Sprintf("%s=%s", ".ROBLOSECURITY", cookie))
	req.Header.Add("Referer", "https://www.roblox.com/games/"+strconv.Itoa(int(placeId)))

	res, err := client.Do(req)
	if err != nil {
		return "", err
	}

	b, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return "", err
	}

	body := string(b)
	if strings.Contains(body, "Guest") {
		return "", errors.New("invalid cookie")
	}

	return body, nil
}

func getCsrfToken(url string) (string, error) {
	res, err := http.Post(url, "application/json", bytes.NewBufferString(""))
	if err != nil {
		return "", err
	}
	defer res.Body.Close()

	io.Copy(ioutil.Discard, res.Body)

	if len(res.Header["X-Csrf-Token"]) < 1 {
		return "", errors.New("failed to obtain csrf token")
	}

	return res.Header["X-Csrf-Token"][0], nil
}

func (session *RobloxSession) GetAuthTicket(placeId uint64) (string, error) {
	return GetAuthTicketWithCookie(session.Cookie, placeId)
}

func (session *RobloxSession) solveCaptcha(twoCaptchaKey string) error {
	captchaSolver := newCaptchaSolver(twoCaptchaKey, "9F35E182-C93C-EBCC-A31D-CF8ED317B996")
	captchaAnswer, err := captchaSolver.SolveCaptcha()
	if err != nil {
		return err
	}

	csrfToken, err := getCsrfToken("https://captcha.roblox.com/v1/funcaptcha/login/web")
	if err != nil {
		return err
	}

	req, _ := http.NewRequest("POST", "https://captcha.roblox.com/v1/funcaptcha/login/web", bytes.NewBufferString("fcToken="+url.QueryEscape(captchaAnswer)+"&credentialsValue="+session.username))
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://www.roblox.com")
	req.Header.Set("Referer", "https://www.roblox.com/login")
	req.Header.Set("X-CSRF-TOKEN", csrfToken)

	res, err := session.Client.Do(req)
	if err != nil {
		return err
	}

	body, _ := phttp.ReadBodyAsString(res.Body)
	if !strings.Contains(body, "{}") {
		return errors.New(body)
	}

	return nil
}

// Login and retrieve session cookie
func (session *RobloxSession) Login(twoCaptchaKey string) error {
	if err := session.solveCaptcha(twoCaptchaKey); err != nil {
		return err
	}

	csrfToken, err := getCsrfToken("https://auth.roblox.com/v2/login")
	if err != nil {
		return err
	}

	payload := fmt.Sprintf(`{"cvalue":"%s","ctype":"Username","password":"%s"}`, session.username, session.password)
	req, _ := http.NewRequest("POST", "https://auth.roblox.com/v2/login", bytes.NewBufferString(payload))
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Origin", "https://www.roblox.com")
	req.Header.Add("X-CSRF-TOKEN", csrfToken)

	res, err := session.Client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	io.Copy(ioutil.Discard, res.Body)

	u, _ := url.Parse("https://www.roblox.com")
	cookies := session.Client.Jar.Cookies(u)
	for _, c := range cookies {
		if c.Name == ".ROBLOSECURITY" {
			session.Cookie = c.Value
			return nil
		}
	}

	return errors.New("session cookie not found")
}
