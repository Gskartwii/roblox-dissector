package main

import (
	"errors"
	"fmt"
	"github.com/local/plib/phttp"
	"net/http"
	"strings"
	"time"
)

type CaptchaSolver struct {
	apiKey, publicKey string
	AnswerTimeout     time.Duration
}

func newCaptchaSolver(apiKey, publicKey string) *CaptchaSolver {
	solver := CaptchaSolver{apiKey: apiKey, publicKey: publicKey, AnswerTimeout: time.Second * 120}
	return &solver
}

func (solver *CaptchaSolver) SolveCaptcha() (result string, err error) {
	taskId := solver.createCaptchaTask()
	return solver.getCaptchaAnswer(taskId)
}

func (solver *CaptchaSolver) createCaptchaTask() string {
	for {
		req, _ := http.NewRequest("GET", fmt.Sprintf("https://2captcha.com/in.php?key=%s&method=funcaptcha&publickey=%s&pageurl=https://www.roblox.com/login", solver.apiKey, solver.publicKey), nil)
		client := http.Client{Timeout: time.Second * 10}

		res, err := client.Do(req)
		if err != nil {
			fmt.Println("error creating captcha task:", err)
		} else {
			body, _ := phttp.ReadBodyAsString(res.Body)
			if strings.Contains(body, "OK") {
				return strings.Split(body, "|")[1]
			} else {
				fmt.Println("error creating captcha task:", body)
			}
		}
		time.Sleep(time.Second * 5)
	}
}

func (solver *CaptchaSolver) getCaptchaAnswer(id string) (answer string, err error) {
	currentTime := time.Now()
	for {
		if time.Since(currentTime) > solver.AnswerTimeout {
			return "", errors.New("error obtaining captcha answer: answer timed out")
		}

		req, _ := http.NewRequest("GET", fmt.Sprintf("http://2captcha.com/res.php?key=%s&action=get&id=%s", solver.apiKey, id), nil)
		client := http.Client{Timeout: time.Second * 10}

		res, err := client.Do(req)
		if err != nil {
			fmt.Println("error obtaining captcha answer:", err)
		} else {
			body, _ := phttp.ReadBodyAsString(res.Body)
			if strings.Contains(body, "OK") {
				return strings.SplitN(body, "|", 2)[1], nil
			}
			if !strings.Contains(body, "CAPCHA_NOT_READY") {
				fmt.Println(body)
			}
		}
		time.Sleep(time.Second * 10)
	}
}
