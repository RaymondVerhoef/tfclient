package main

import (
	"bytes"
	b64 "encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/olebedev/config"
)

// Must be this exact date-time
const datelo = "2006-01-02"
const timelo = "2006-01-02T15:04:05Z"

var host = ""
var httplog = false
var clientid = ""
var clientsecret = ""
var methods = []string{"POST", "PUT", "PATCH", "DELETE", "HEAD", "GET", "OPTIONS", "TRACE"}
var nobody = []string{"HEAD", "GET", "OPTIONS", "TRACE"}

type Errs struct {
	Errors []struct {
		Code        string `json:"code"`
		Field       string `json:"field"`
		Description string `json:"description"`
	} `json:"errors"`
}
type Action struct {
	File   string
	Parms  string
	Obj    string
	Action string
	Url    string
}
type Attachment struct {
	AttachmentId     string `json:"attachmentId"`
	Content          string `json:"content"`
	MimeType         string `json:"mimeType"`
	Name             string `json:"name"`
	OriginalFileName string `json:"originalFileName"`
	Sealed           bool   `json:"sealed"`
	Size             int    `json:"size"`
	Type             string `json:"type"`
}
type Reference struct {
	ReferenceId string `json:"referenceId"`
	Name        string `json:"name"`
	Value       string `json:"value"`
}
type Login struct {
	AccessToken   string `json:"access_token"`
	AccountId     string `json:"accountId"`
	AccountNumber string `json:"accountNumber"`
	AccountSecret string `json:"accountSecret"`
	Credits       int    `json:"credits"`
	Email         string `json:"email"`
	ExpiresIn     int    `json:"expires_in"`
	PhoneNumber   string `json:"phoneNumber"`
	RefreshToken  string `json:"refresh_token"`
}
type Account struct {
	AccountId   string `json:"accountId"`
	Email       string `json:"email"`
	Name        string `json:"name"`
	Password    string `json:"password"`
	PhoneNumber string `json:"phoneNumber"`
}
type Role struct {
	AccountId                    string `json:"accountId"`
	BuildingNumber               string `json:"buildingNumber"`
	CityName                     string `json:"cityName"`
	ContactEmailAddress          string `json:"contactEmailAddress"`
	ContactName                  string `json:"contactName"`
	ContactNote                  string `json:"contactNote"`
	ContactPhoneNumber           string `json:"contactPhoneNumber"`
	CountryCode                  string `json:"countryCode"`
	CountryName                  string `json:"countryName"`
	Name                         string `json:"name"`
	PostalBox                    string `json:"postalBox"`
	PostalCode                   string `json:"postalCode"`
	RoleID                       string `json:"roleId"`
	StreetName                   string `json:"streetName"`
	SubmittedAccountEmailAddress string `json:"submittedAccountEmailAddress"`
	SubmittedAccountNumber       string `json:"submittedAccountNumber"`
}

var currentlogin Login
var submitter Account
var consignor Account
var consignee Account
var carrier Account
var delconsignor Account
var delconsignee Account
var delcarrier Account
var subscarriers []Account

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func basicAuthEnc(id string, secret string) string {
	data := id + ":" + secret
	enc := b64.StdEncoding.EncodeToString([]byte(data))
	return "Basic " + enc
}

func stringInSlice(a string, list []string) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}

func capitalize(s string) string {
	if s == "" {
		return ""
	}
	r, n := utf8.DecodeRuneInString(s)
	return string(unicode.ToUpper(r)) + s[n:]
}

func fillStruct(m map[string]interface{}, s interface{}) error {
	structValue := reflect.ValueOf(s).Elem()

	for name, value := range m {

		Name := capitalize(name)

		if !structValue.IsValid() {
			continue
		}
		structFieldValue := structValue.FieldByName(Name)

		if !structFieldValue.IsValid() {
			return fmt.Errorf("No such field: %s in obj", Name)
		}

		if !structFieldValue.CanSet() {
			return fmt.Errorf("Cannot set %s field value", Name)
		}

		val := reflect.ValueOf(value)
		if structFieldValue.Type() != val.Type() {
			return fmt.Errorf("Provided value type didn't match obj field type")
		}

		structFieldValue.Set(val)
	}
	return nil
}

func login(account Account, refreshtoken string) int {
	var errors Errs
	if refreshtoken == "" && (account.Name == "" || account.Password == "") {
		return 800
	}

	var reqbody = url.Values{}
	if refreshtoken == "" {
		reqbody.Set("grant_type", "password")
		reqbody.Add("username", account.Email)
		reqbody.Add("password", account.Password)
		reqbody.Add("scope", "transfollow")
	} else {
		reqbody.Set("grant_type", "refresh_token")
		reqbody.Add("refresh_token", refreshtoken)
		reqbody.Add("scope", "transfollow")
	}
	var resbody = ""
	var resbytes = []byte(resbody)

	url := "https://" + host + "/oauth/token"
	auth := basicAuthEnc(clientid, clientsecret)
	req, err := http.NewRequest("POST", url, bytes.NewBufferString(reqbody.Encode()))
	check(err)
	req.Header.Set("Authorization", auth)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Content-Length", strconv.Itoa(len(reqbody.Encode())))

	client := &http.Client{}
	resp, err := client.Do(req)
	check(err)
	defer resp.Body.Close()
	resbytes, _ = ioutil.ReadAll(resp.Body)
	status := resp.StatusCode
	if httplog {
		fmt.Println("REQUEST")
		fmt.Println("POST", "/oauth/token")
		for k, v := range req.Header {
			fmt.Println(k+":", v)
		}
		reqbodystr := reqbody.Encode()
		if len(reqbodystr) > 0 {
			fmt.Println(" ")
			fmt.Println(reqbodystr)
		}

		fmt.Println("RESPONSE")
		fmt.Println("Status", resp.StatusCode)
		if len(string(resbytes)) > 0 {
			fmt.Println(" ")
			fmt.Println(string(resbytes))
		}

	}
	if status == 200 {
		jsonerr := json.Unmarshal(resbytes, &currentlogin)
		check(jsonerr)
		if refreshtoken == "" {
			url := "/accounts/users/me"
			status, resbytes, _ = callApi("GET", url, "Bearer "+currentlogin.AccessToken, "")
			if status == 200 {
				jsonerr = json.Unmarshal(resbytes, &currentlogin)
				check(jsonerr)
			} else if status >= 400 {
				jsonerr := json.Unmarshal(resbytes, &errors)
				check(jsonerr)
				fmt.Println("Endpoint ./me error:", errors.Errors[0].Code, errors.Errors[0].Field, errors.Errors[0].Description)
			}
		}
	} else if status >= 400 {
		jsonerr := json.Unmarshal(resbytes, &errors)
		check(jsonerr)
		for _, ers := range errors.Errors {
			fmt.Println("Error:", ers.Code, ers.Field, ers.Description)
		}
	}

	return status
}

func createAccount(filename string, acc Account) (int, []byte, string) {

	template, err := ioutil.ReadFile(filename)
	check(err)
	cfg_str := strings.TrimSpace(string(template))
	reqbody := strings.Replace(cfg_str, "{{name}}", acc.Name, -1)
	reqbody = strings.Replace(reqbody, "{{email}}", acc.Email, -1)
	reqbody = strings.Replace(reqbody, "{{password}}", acc.Password, -1)

	status, resbytes, timelog := doCall("POST", "/accounts/users", basicAuthEnc(clientid, clientsecret), reqbody)
	return status, resbytes, timelog
}

func isOnline(host string) bool {
	url := "/heartbeat"
	status, _, _ := callApi("GET", url, "", "")
	return status == 200
}

func refreshToken() int {
	var account *Account
	return login(*account, currentlogin.RefreshToken)
}

func callApi(method string, url string, auth string, reqbody string) (int, []byte, string) {
	var resbody = ""
	var resbytes = []byte(resbody)
	var reqbytes = []byte(reqbody)

	req, err := http.NewRequest(method, "https://"+host+url, bytes.NewBuffer(reqbytes))
	check(err)

	req.Header.Set("Authorization", auth)
	req.Header.Set("Accept", "application/json")
	if stringInSlice(method, nobody) == false {
		req.Header.Set("Content-Type", "application/json")
		if len(reqbody) > 0 {
			req.Header.Set("Content-Length", strconv.Itoa(len(reqbody)))
		}
	}
	client := &http.Client{}
	start := time.Now()
	resp, err := client.Do(req)
	check(err)
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 500 {
		resbytes, _ = ioutil.ReadAll(resp.Body)
	}

	if httplog {
		fmt.Println("REQUEST")
		fmt.Println(method, req.URL)
		for k, v := range req.Header {
			fmt.Println(k+":", v)
		}

		if len(reqbody) > 0 {
			fmt.Println(" ")
			fmt.Println(reqbody)
		}

		fmt.Println("RESPONSE")
		fmt.Println("Status", resp.StatusCode)
		if len(string(resbytes)) > 0 {
			fmt.Println(" ")
			fmt.Println(string(resbytes))
		}
	}

	elapsed := time.Since(start)
	timelog := fmt.Sprintf("%s %s in %d ms.", method, url, elapsed/time.Millisecond)

	return resp.StatusCode, resbytes, timelog
}

func doCall(method string, url string, auth string, reqbody string) (int, []byte, string) {
	var errors Errs
	status, resbytes, timelog := callApi(method, url, auth, reqbody)

	if status >= 400 {
		jsonerr := json.Unmarshal(resbytes, &errors)
		check(jsonerr)
		for _, ers := range errors.Errors {
			fmt.Println("Error:", ers.Code, ers.Field, ers.Description)
		}
	}

	return status, resbytes, timelog
}

func makeAccountStruct(cfg *config.Config, account string, structure *Account) {
	accountmap, err := cfg.Map("accounts." + account)
	check(err)
	err = fillStruct(accountmap, structure)
	check(err)
}

func parseConfigString(cfg_str string) (*config.Config, error) {
	var err error
	var cfg *config.Config

	if string([]rune(cfg_str)[1]) == "{" {
		cfg, err = config.ParseJson(cfg_str)

	} else {
		cfg, err = config.ParseYaml(cfg_str)
	}

	return cfg, err
}

func main() {
	var cfg *config.Config
	var cfgfile = ""
	var stepfile = ""
	var environment = ""

	var status = 0
	var resbytes []byte
	var timelog = ""

	var account *Account
	var currentfd = ""
	var previouscommits []interface{}

	argsWithProg := os.Args
	if len(argsWithProg) > 3 {
		cfgfile = os.Args[1]
		stepfile = os.Args[2]
		environment = os.Args[3]
	} else {
		fmt.Printf("Usage:\n%v config-filename step-filename environment\nIf no paths are given the current dir is assumed\n\n", os.Args[0])
		os.Exit(1)
	}

	cfg_string, err := ioutil.ReadFile(cfgfile)
	cfg_str := strings.TrimSpace(string(cfg_string))
	check(err)

	cfg, err = parseConfigString(cfg_str)
	check(err)

	httplog, err = cfg.Bool("httplog")

	env, err := cfg.Get(environment)
	check(err)
	host, err = env.String("api.host")
	portal, _ := env.String("portal.host")
	check(err)

	makeAccountStruct(cfg, "submitter", &submitter)
	makeAccountStruct(cfg, "consignor", &consignor)
	makeAccountStruct(cfg, "consignee", &consignee)
	makeAccountStruct(cfg, "carrier", &carrier)

	fmt.Println("-----------------------------------------------------------------")
	fmt.Println("Start")
	fmt.Println("-----------------------------------------------------------------")
	if isOnline(host) {
		fmt.Println("Environment:", host)
		clientid, _ = env.String("client.id")
		clientsecret, _ = env.String("client.secret")

		step_string, err := ioutil.ReadFile(stepfile)
		step_str := strings.TrimSpace(string(step_string))
		check(err)

		stepcfg, err := parseConfigString(step_str)
		steps, _ := stepcfg.Get("steps")
		check(err)
		currentfd, err = stepcfg.String("currentfd")

	StepLoop:
		for i, actionmap := range steps.Root.([]interface{}) {

			var action Action
			err = fillStruct(actionmap.(map[string]interface{}), &action)
			check(err)

			switch {

			case action.Action == "getfd":
				if len(currentfd) > 0 {
					action.Url = strings.Replace(action.Url, "{{id}}", currentfd, 1)
				}
				fmt.Println("-----------------------------------------------------------------")
				fmt.Println("Step", i+1)
				fmt.Printf("GET %s \n", action.Url)
				fmt.Println("-----------------------------------------------------------------")

				status, resbytes, timelog = doCall("GET", action.Url, "Bearer "+currentlogin.AccessToken, "")
				if status == 200 {
					resp := strings.Replace(string(resbytes), ":null", ":\"\"", -1)
					result, err := config.ParseJson(resp)
					check(err)
					currentfd, err = result.String("freightDocumentId")
					previouscommits, _ = result.List("previousCommits")
					check(err)
					if len(currentfd) > 0 {
						fmt.Printf("FD %s with PC %s\n", currentfd, previouscommits)
					}
				}
				log.Printf("%s with status %d", timelog, status)

			case action.Action == "issuefd":
				if len(currentfd) > 0 {
					action.Url = strings.Replace(action.Url, "{{id}}", currentfd, 1)
				}
				fmt.Println("-----------------------------------------------------------------")
				fmt.Println("Step", i+1)
				fmt.Printf("POST %s \n", action.Url)
				fmt.Println("-----------------------------------------------------------------")

				status, resbytes, timelog = doCall("POST", action.Url, "Bearer "+currentlogin.AccessToken, "")
				log.Printf("%s with status %d", timelog, status)

			case action.Action == "createfd" || action.Action == "updatefd":
				var oldattachments []Attachment
				var oldreferences []Reference
				var method = "PUT"
				if action.Action == "createfd" {
					method = "POST"
				} else {
					action.Url = strings.Replace(action.Url, "{{id}}", currentfd, 1)
				}

				fmt.Println("-----------------------------------------------------------------")
				fmt.Println("Step", i+1)
				fmt.Printf("%s %s with file %s (parms %s subj %s)\n", method, action.Url, action.File, action.Parms, action.Obj)
				fmt.Println("-----------------------------------------------------------------")

				template, err := ioutil.ReadFile(action.File)
				check(err)
				reqbody := strings.TrimSpace(string(template))
				//parseConfigString chokes on null values
				reqbody = strings.Replace(reqbody, ": null", ": \"~null~\"", -1)
				now := time.Now()
				reqbody = strings.Replace(reqbody, "{{ed}}", now.Format(datelo), 1)
				reqbody = strings.Replace(reqbody, "{{adt}}", now.Add(24*time.Hour).Format(datelo), 1)
				reqbody = strings.Replace(reqbody, "{{edtt}}", now.Add(24*time.Hour).Format(timelo), 1)
				reqbody = strings.Replace(reqbody, "{{edtd}}", now.Add(48*time.Hour).Format(timelo), 1)
				if action.Action == "updatefd" {
					var req *config.Config
					req, err = parseConfigString(reqbody)
					check(err)

					oldatts, _ := req.Get("attachments")
					for _, attmap := range oldatts.Root.([]interface{}) {
						var attachment Attachment
						err = fillStruct(attmap.(map[string]interface{}), &attachment)
						check(err)
						oldattachments = append(oldattachments, attachment)
					}

					oldrefs, _ := req.Get("references")
					for _, refmap := range oldrefs.Root.([]interface{}) {
						var reference Reference
						err = fillStruct(refmap.(map[string]interface{}), &reference)
						check(err)
						oldreferences = append(oldreferences, reference)
					}
				}

				if len(action.Parms) > 0 {
					var i int = 0
					var parmscfg *config.Config
					parmscfg, err := parseConfigString(action.Parms)
					check(err)

					var attachments []Attachment
					atts, _ := parmscfg.Get("attachments")
					for _, attmap := range atts.Root.([]interface{}) {
						var attachment Attachment
						err = fillStruct(attmap.(map[string]interface{}), &attachment)
						check(err)
						f, err := os.Open(attachment.Name)
						if err == nil {
							f.Close()
							data, err := ioutil.ReadFile(attachment.Name)
							check(err)
							attachment.Content = b64.StdEncoding.EncodeToString(data)
							attachment.OriginalFileName, err = filepath.Abs(filepath.Dir(attachment.Name))
							_, attachment.Name = path.Split(attachment.Name)
							attachment.OriginalFileName = attachment.OriginalFileName + "/" + attachment.Name
							attachments = append(attachments, attachment)
							i++
						} else {
							fmt.Println("Could not find", attachment.Name)
						}
					}
					var references []Reference
					refs, _ := parmscfg.Get("references")
					for _, refmap := range refs.Root.([]interface{}) {
						var reference Reference
						err = fillStruct(refmap.(map[string]interface{}), &reference)
						check(err)
						references = append(references, reference)
					}

					if action.Action == "updatefd" {
						oldattachments = append(oldattachments, attachments...)
						oldreferences = append(oldreferences, references...)
					}

					jsonb, _ := json.Marshal(oldattachments)
					if string(jsonb) != "null" {
						r := regexp.MustCompile(`"attachments": *(?s)(.*?)\[(.*?)\]`)
						reqbody = r.ReplaceAllString(reqbody, "\"attachments\": "+string(jsonb))
					}

					jsonb, _ = json.Marshal(oldreferences)
					if string(jsonb) != "null" {
						r := regexp.MustCompile(`"references": *(?s)(.*?)\[(.*?)\]`)
						reqbody = r.ReplaceAllString(reqbody, "\"references\": "+string(jsonb))
					}
				}

				reqbody = strings.Replace(reqbody, ": \"~null~\"", ": null", -1)
				status, resbytes, timelog = doCall(method, action.Url, "Bearer "+currentlogin.AccessToken, reqbody)
				if status == 201 {
					result, err := config.ParseJson(string(resbytes))
					check(err)
					currentfd, err = result.String("freightDocumentId")
					check(err)
					if len(currentfd) > 0 {
						fmt.Printf("new FD at https://%s/#home,viewFreightDocument&id=%s\n", portal, currentfd)
					}
				} else if status == 205 {
					if len(currentfd) > 0 {
						fmt.Printf("changed FD at https://%s/#home,viewFreightDocument&id=%s\n", portal, currentfd)
					}
				}
				log.Printf("%s with status %d", timelog, status)

			case action.Action == "delegatefd":
				if len(currentfd) > 0 {
					action.Url = strings.Replace(action.Url, "{{id}}", currentfd, 1)
				}
				fmt.Println("-----------------------------------------------------------------")
				fmt.Println("Step", i+1)
				fmt.Printf("POST %s with file %s (parms %s subj %s)\n", action.Url, action.File, action.Parms, action.Obj)
				fmt.Println("-----------------------------------------------------------------")

				if len(currentfd) > 0 {
					template, err := ioutil.ReadFile(action.File)
					check(err)
					reqbody := strings.TrimSpace(string(template))

					status, resbytes, timelog = doCall("POST", action.Url, "Bearer "+currentlogin.AccessToken, reqbody)
					if status >= 400 {
						fmt.Println("%s", string(resbytes))
					}
					log.Printf("%s with status %d", timelog, status)
				} else {
					fmt.Println("freightDocumentId is missing")
					break StepLoop
				}
			case action.Action == "login":
				fmt.Println("-----------------------------------------------------------------")
				fmt.Println("Step", i+1)
				fmt.Println("Log in as", action.Obj)
				fmt.Println("-----------------------------------------------------------------")

				switch {
				case action.Obj == "submitter":
					account = &submitter
				case action.Obj == "consignor":
					account = &consignor
				case action.Obj == "consignee":
					account = &consignee
				case action.Obj == "carrier":
					account = &carrier
				case action.Obj == "delconsignor":
					account = &delconsignor
				case action.Obj == "delconsignee":
					account = &delconsignee
				case action.Obj == "delcarrier":
					account = &delcarrier
				}
				status = login(*account, "")
				if status == 200 {
					fmt.Println("Logged in as", account.Name)
				} else if status == 800 {
					fmt.Println("No credentials found to log in with")
				} else {
					break StepLoop
				}

			case action.Action == "createaccount":
				fmt.Println("-----------------------------------------------------------------")
				fmt.Println("Step", i+1)
				fmt.Printf("Creating account %s with file %s\n", action.Obj, action.File)
				fmt.Println("-----------------------------------------------------------------")

				switch {
				case action.Obj == "submitter":
					account = &submitter
				case action.Obj == "consignor":
					account = &consignor
				case action.Obj == "consignee":
					account = &consignee
				case action.Obj == "carrier":
					account = &carrier
				case action.Obj == "delconsignor":
					account = &delconsignor
				case action.Obj == "delconsignee":
					account = &delconsignee
				case action.Obj == "delcarrier":
					account = &delcarrier
				}
				status, resbytes, timelog = createAccount(action.File, *account)
				log.Printf("%s with status %d", timelog, status)
			}

		}
	} else {
		fmt.Println("Offline:", host)
	}
	fmt.Println("-----------------------------------------------------------------")
	fmt.Println("End")
	fmt.Println("-----------------------------------------------------------------")
}
