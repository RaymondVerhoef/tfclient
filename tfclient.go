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

type Account struct {
	AccountId   string `json:"accountId"`
	Email       string `json:"email"`
	Name        string `json:"name"`
	Password    string `json:"password"`
	PhoneNumber string `json:"phoneNumber"`
}
type Errs struct {
	Errors []struct {
		Code        string `json:"code"`
		Field       string `json:"field"`
		Description string `json:"description"`
	} `json:"errors"`
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
type Step struct {
	File   string
	Parms  string
	Obj    string
	Action string
	Url    string
}

type Approval struct {
	Action   string `json:"action"`
	Evidence struct {
		Attachments []struct {
			Content          string `json:"content"`
			MimeType         string `json:"mimeType"`
			Name             string `json:"name"`
			OriginalFileName string `json:"originalFileName"`
		} `json:"attachments"`
		ResponseCode    string `json:"responseCode"`
		SignedOnGlassBy struct {
			Email string `json:"email"`
			Name  string `json:"name"`
		} `json:"signedOnGlassBy"`
	} `json:"evidence"`
	Location struct {
		Latitude  string `json:"latitude"`
		Longitude string `json:"longitude"`
	} `json:"location"`
	OwnRole              string   `json:"ownRole"`
	Place                string   `json:"place"`
	PreviousCommits      []string `json:"previousCommits"`
	SecondsSinceCreation int      `json:"secondsSinceCreation"`
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
type Comment struct {
	Attachments []struct {
		Content          string `json:"content"`
		Name             string `json:"name"`
		OriginalFileName string `json:"originalFileName"`
		Sealed           bool   `json:"sealed"`
		Type             string `json:"type"`
	} `json:"attachments"`
	ClientMeta           string        `json:"clientMeta"`
	PreviousCommits      []interface{} `json:"previousCommits"`
	SecondsSinceCreation int           `json:"secondsSinceCreation"`
	Text                 string        `json:"text"`
}
type OwnPermission struct {
	Permissions []string `json:"permissions"`
	Role        string   `json:"role"`
}
type Reference struct {
	ReferenceId string `json:"referenceId"`
	Name        string `json:"name"`
	Value       string `json:"value"`
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
type Update struct {
	NewFreightDocumentStatus string   `json:"newFreightDocumentStatus"`
	PreviousCommits          []string `json:"previousCommits"`
	SecondsSinceCreation     int      `json:"secondsSinceCreation"`
}

type Fd struct {
	AgreedDateOfTakingOver        string          `json:"agreedDateOfTakingOver"`
	Approvals                     []Approval      `json:"approvals"`
	Attachments                   []Attachment    `json:"attachments"`
	Carrier                       Role            `json:"carrier"`
	CarrierCode                   string          `json:"carrierCode"`
	Comments                      []Comment       `json:"comments"`
	Consignee                     Role            `json:"consignee"`
	Consignor                     Role            `json:"consignor"`
	DeliveryDate                  string          `json:"deliveryDate"`
	EstablishedDate               string          `json:"establishedDate"`
	EstablishedPlace              string          `json:"establishedPlace"`
	EstimatedDateTimeOfDelivery   string          `json:"estimatedDateTimeOfDelivery"`
	EstimatedDateTimeOfTakingOver string          `json:"estimatedDateTimeOfTakingOver"`
	FreightDocumentID             string          `json:"freightDocumentId"`
	Goods                         string          `json:"goods"`
	LastModifiedDateTime          string          `json:"lastModifiedDateTime"`
	OwnPermissions                []OwnPermission `json:"ownPermissions"`
	PaymentForCarriage            string          `json:"paymentForCarriage"`
	PlaceOfDelivery               *Role           `json:"placeOfDelivery",omitempty`
	PlaceOfTakingOver             *Role           `json:"placeOfTakingOver",omitempty`
	PreviousCommits               []string        `json:"previousCommits"`
	References                    []Reference     `json:"references"`
	ReimbursementAmount           float64         `json:"reimbursementAmount"`
	ReimbursementCurrency         string          `json:"reimbursementCurrency"`
	SenderInstructions            string          `json:"senderInstructions"`
	SpecialAgreements             string          `json:"specialAgreements"`
	Status                        string          `json:"status"`
	SubmitterAccountID            string          `json:"submitterAccountId"`
	SubmitterName                 string          `json:"submitterName"`
	SubsequentCarriers            []Role          `json:"subsequentCarriers"`
	TransFollowNumber             string          `json:"transFollowNumber"`
	TransportConditions           string          `json:"transportConditions"`
	Type                          string          `json:"type"`
	Updates                       []Update        `json:"updates"`
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
				for _, ers := range errors.Errors {
					fmt.Println("Error:", ers.Code, ers.Field, ers.Description)
				}
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

func makeNewAttachments(jsonstr string) []Attachment {
	type Attachments struct {
		Attachments []Attachment
	}
	var atts Attachments
	jsonerr := json.Unmarshal([]byte(jsonstr), &atts)
	check(jsonerr)
	var attachments []Attachment
	for i, _ := range atts.Attachments {
		// pointers to slice members prevent copies
		attachment := &atts.Attachments[i]
		if len(attachment.OriginalFileName) == 0 {
			f, err := os.Open(attachment.Name)
			if err == nil {
				f.Close()
				data, err := ioutil.ReadFile(attachment.Name)
				check(err)
				attachment.Content = b64.StdEncoding.EncodeToString(data)
				attachment.OriginalFileName, err = filepath.Abs(filepath.Dir(attachment.Name))
				_, attachment.Name = path.Split(attachment.Name)
				attachment.OriginalFileName = attachment.OriginalFileName + "/" + attachment.Name
				attachments = append(attachments, *attachment)
			} else {
				fmt.Println("Could not find", attachment.Name)
			}
		}
	}
	return attachments
}

func combineAttachments(old []Attachment, new []Attachment) []Attachment {
	var attachments []Attachment
	for i, _ := range old {
		// pointers to slice members prevent copies
		oldatt := &old[i]
		for j, _ := range new {
			newatt := &new[j]
			if newatt.AttachmentId == oldatt.AttachmentId {
				if len(newatt.Content) > 0 {
					oldatt.Content = newatt.Content
				}
				if len(newatt.Name) > 0 {
					oldatt.Name = newatt.Name
				}
				if len(newatt.OriginalFileName) > 0 {
					oldatt.OriginalFileName = newatt.OriginalFileName
				}
				oldatt.Sealed = newatt.Sealed
				oldatt.Size = newatt.Size
				attachments = append(attachments, *oldatt)
			} else {
				attachments = append(attachments, *newatt)
			}
		}
	}
	return attachments
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

	var currentaccount *Account
	var currentfdid = ""
	var currentfd *Fd = nil
	var previouscommits []string

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
		currentfdid, err = stepcfg.String("currentfd")

	StepLoop:
		for i, stepmap := range steps.Root.([]interface{}) {

			var step Step
			err = fillStruct(stepmap.(map[string]interface{}), &step)
			check(err)

			switch {

			case step.Action == "getfd":
				if len(currentfdid) > 0 {
					step.Url = strings.Replace(step.Url, "{{id}}", currentfdid, 1)
				}
				fmt.Println("-----------------------------------------------------------------")
				fmt.Println("Step", i+1)
				fmt.Printf("GET %s \n", step.Url)
				fmt.Println("-----------------------------------------------------------------")

				status, resbytes, timelog = doCall("GET", step.Url, "Bearer "+currentlogin.AccessToken, "")
				if status == 200 {
					jsonerr := json.Unmarshal(resbytes, &currentfd)
					check(jsonerr)
					currentfdid = currentfd.FreightDocumentID
					previouscommits = currentfd.PreviousCommits

					if len(currentfdid) > 0 {
						fmt.Printf("FD %s with PC %s\n", currentfdid, previouscommits)
					}
				}
				log.Printf("%s with status %d", timelog, status)

			case step.Action == "issuefd":
				if len(currentfdid) > 0 {
					step.Url = strings.Replace(step.Url, "{{id}}", currentfdid, 1)
				}
				fmt.Println("-----------------------------------------------------------------")
				fmt.Println("Step", i+1)
				fmt.Printf("POST %s \n", step.Url)
				fmt.Println("-----------------------------------------------------------------")

				status, resbytes, timelog = doCall("POST", step.Url, "Bearer "+currentlogin.AccessToken, "")
				log.Printf("%s with status %d", timelog, status)

			case step.Action == "createfd" || step.Action == "updatefd":

				var oldattachments []Attachment
				var newattachments []Attachment
				var method = "PUT"

				if step.Action == "createfd" {
					method = "POST"
				} else {
					step.Url = strings.Replace(step.Url, "{{id}}", currentfdid, 1)
					oldattachments = currentfd.Attachments
				}

				fmt.Println("-----------------------------------------------------------------")
				fmt.Println("Step", i+1)
				fmt.Printf("%s %s with file %s (parms %s subj %s)\n", method, step.Url, step.File, step.Parms, step.Obj)
				fmt.Println("-----------------------------------------------------------------")
				if len(step.File) > 0 {
					template, err := ioutil.ReadFile(step.File)
					check(err)
					templatestr := strings.TrimSpace(string(template))
					now := time.Now()
					templatestr = strings.Replace(templatestr, "{{ed}}", now.Format(datelo), 1)
					templatestr = strings.Replace(templatestr, "{{adt}}", now.Add(24*time.Hour).Format(datelo), 1)
					templatestr = strings.Replace(templatestr, "{{edtt}}", now.Add(24*time.Hour).Format(timelo), 1)
					templatestr = strings.Replace(templatestr, "{{edtd}}", now.Add(48*time.Hour).Format(timelo), 1)
					jsonerr := json.Unmarshal([]byte(templatestr), &currentfd)
					oldattachments = combineAttachments(oldattachments, currentfd.Attachments)
					check(jsonerr)
				}

				if currentfd != nil {

					if len(step.Parms) > 0 {
						newattachments = makeNewAttachments(step.Parms)
					}
					currentfd.Attachments = combineAttachments(oldattachments, newattachments)

					newfdjson, _ := json.Marshal(currentfd)
					reqbody := string(newfdjson)
					r := regexp.MustCompile(`"submitterAccountId": *(?s)(.*?)\"(.*?)\"`)
					reqbody = r.ReplaceAllString(reqbody, "\"submitterAccountId\":null")
					r = regexp.MustCompile(`"lastModifiedDateTime": *(?s)(.*?)\"(.*?)\"`)
					reqbody = r.ReplaceAllString(reqbody, "\"lastModifiedDateTime\":null")

					status, resbytes, timelog = doCall(method, step.Url, "Bearer "+currentlogin.AccessToken, reqbody)
					if status == 201 {
						result, err := config.ParseJson(string(resbytes))
						check(err)
						currentfdid, err = result.String("freightDocumentId")
						check(err)
						if len(currentfdid) > 0 {
							fmt.Printf("new FD at https://%s/#home,viewFreightDocument&id=%s\n", portal, currentfdid)
						}
					} else if status == 205 {
						if len(currentfdid) > 0 {
							fmt.Printf("changed FD at https://%s/#home,viewFreightDocument&id=%s\n", portal, currentfdid)
						}
					}
					log.Printf("%s with status %d", timelog, status)
				} else {
					fmt.Println("freightDocument content is missing")
					break StepLoop
				}

			case step.Action == "delegatefd":
				if len(currentfdid) > 0 {
					step.Url = strings.Replace(step.Url, "{{id}}", currentfdid, 1)
				}
				fmt.Println("-----------------------------------------------------------------")
				fmt.Println("Step", i+1)
				fmt.Printf("POST %s with file %s (parms %s subj %s)\n", step.Url, step.File, step.Parms, step.Obj)
				fmt.Println("-----------------------------------------------------------------")

				if len(currentfdid) > 0 {
					template, err := ioutil.ReadFile(step.File)
					check(err)
					reqbody := strings.TrimSpace(string(template))

					status, resbytes, timelog = doCall("POST", step.Url, "Bearer "+currentlogin.AccessToken, reqbody)

					log.Printf("%s with status %d", timelog, status)
				} else {
					fmt.Println("freightDocumentId is missing")
					break StepLoop
				}

			case step.Action == "createcomment":
				var attachments []Attachment
				if len(currentfdid) > 0 {
					step.Url = strings.Replace(step.Url, "{{id}}", currentfdid, 1)
				}
				fmt.Println("-----------------------------------------------------------------")
				fmt.Println("Step", i+1)
				fmt.Printf("POST %s with file %s (parms %s subj %s)\n", step.Url, step.File, step.Parms, step.Obj)
				fmt.Println("-----------------------------------------------------------------")

				if len(currentfdid) > 0 {
					template, err := ioutil.ReadFile(step.File)
					check(err)
					reqbody := strings.TrimSpace(string(template))
					if len(previouscommits) > 0 {
						pc, err := json.Marshal(previouscommits)
						check(err)
						r := regexp.MustCompile(`"previousCommits": *(?s)(.*?)\[(.*?)\]`)
						reqbody = r.ReplaceAllString(reqbody, "\"previousCommits\": "+string(pc))
					}

					if len(step.Parms) > 0 {
						attachments = makeNewAttachments(step.Parms)
						if len(attachments) > 0 {
							att, err := json.Marshal(attachments)
							check(err)
							r := regexp.MustCompile(`"attachments": *(?s)(.*?)\[(.*?)\]`)
							reqbody = r.ReplaceAllString(reqbody, "\"attachments\": "+string(att))
						}
					}
					status, resbytes, timelog = doCall("POST", step.Url, "Bearer "+currentlogin.AccessToken, reqbody)

					log.Printf("%s with status %d", timelog, status)
				} else {
					fmt.Println("freightDocumentId is missing")
					break StepLoop
				}

			case step.Action == "submitmyapproval":
				if len(currentfdid) > 0 {
					step.Url = strings.Replace(step.Url, "{{id}}", currentfdid, 1)
				}
				fmt.Println("-----------------------------------------------------------------")
				fmt.Println("Step", i+1)
				fmt.Printf("POST %s with file %s (parms %s subj %s)\n", step.Url, step.File, step.Parms, step.Obj)
				fmt.Println("-----------------------------------------------------------------")

				if len(currentfdid) > 0 {
					template, err := ioutil.ReadFile(step.File)
					check(err)
					reqbody := strings.TrimSpace(string(template))
					if len(step.Parms) > 0 && len(step.Obj) > 0 {
						reqbody = strings.Replace(reqbody, "{{ownrole}}", step.Parms, 1)
						reqbody = strings.Replace(reqbody, "{{transfer}}", step.Obj, 1)
						if len(previouscommits) > 0 {
							pc, err := json.Marshal(previouscommits)
							check(err)
							r := regexp.MustCompile(`"previousCommits": *(?s)(.*?)\[(.*?)\]`)
							reqbody = r.ReplaceAllString(reqbody, "\"previousCommits\": "+string(pc))
						}

						status, resbytes, timelog = doCall("POST", step.Url, "Bearer "+currentlogin.AccessToken, reqbody)

						log.Printf("%s with status %d", timelog, status)
					} else {
						fmt.Println("Parms role and/or Obj transfer missing in scenario file")
					}
				} else {
					fmt.Println("freightDocumentId is missing")
					break StepLoop
				}

			case step.Action == "updatestatus":
				if len(currentfdid) > 0 {
					step.Url = strings.Replace(step.Url, "{{id}}", currentfdid, 1)
				}
				fmt.Println("-----------------------------------------------------------------")
				fmt.Println("Step", i+1)
				fmt.Printf("POST %s with file %s (parms %s subj %s)\n", step.Url, step.File, step.Parms, step.Obj)
				fmt.Println("-----------------------------------------------------------------")

				if len(currentfdid) > 0 {
					template, err := ioutil.ReadFile(step.File)
					check(err)
					reqbody := strings.TrimSpace(string(template))
					if len(step.Obj) > 0 {
						reqbody = strings.Replace(reqbody, "{{newstatus}}", step.Obj, 1)
						if len(previouscommits) > 0 {
							pc, err := json.Marshal(previouscommits)
							check(err)
							r := regexp.MustCompile(`"previousCommits": *(?s)(.*?)\[(.*?)\]`)
							reqbody = r.ReplaceAllString(reqbody, "\"previousCommits\": "+string(pc))
						}

						status, resbytes, timelog = doCall("POST", step.Url, "Bearer "+currentlogin.AccessToken, reqbody)

						log.Printf("%s with status %d", timelog, status)
					} else {
						fmt.Println("Obj newstatus missing in scenario file")
					}
				} else {
					fmt.Println("freightDocumentId is missing")
					break StepLoop
				}

			case step.Action == "login":
				fmt.Println("-----------------------------------------------------------------")
				fmt.Println("Step", i+1)
				fmt.Println("Log in as", step.Obj)
				fmt.Println("-----------------------------------------------------------------")

				switch {
				case step.Obj == "submitter":
					currentaccount = &submitter
				case step.Obj == "consignor":
					currentaccount = &consignor
				case step.Obj == "consignee":
					currentaccount = &consignee
				case step.Obj == "carrier":
					currentaccount = &carrier
				case step.Obj == "delconsignor":
					currentaccount = &delconsignor
				case step.Obj == "delconsignee":
					currentaccount = &delconsignee
				case step.Obj == "delcarrier":
					currentaccount = &delcarrier
				}
				status = login(*currentaccount, "")
				if status == 200 {
					fmt.Println("Logged in as", currentaccount.Name)
				} else if status == 800 {
					fmt.Println("No credentials found to log in with")
				} else {
					break StepLoop
				}

			case step.Action == "createaccount":
				fmt.Println("-----------------------------------------------------------------")
				fmt.Println("Step", i+1)
				fmt.Printf("Creating account %s with file %s\n", step.Obj, step.File)
				fmt.Println("-----------------------------------------------------------------")

				switch {
				case step.Obj == "submitter":
					currentaccount = &submitter
				case step.Obj == "consignor":
					currentaccount = &consignor
				case step.Obj == "consignee":
					currentaccount = &consignee
				case step.Obj == "carrier":
					currentaccount = &carrier
				case step.Obj == "delconsignor":
					currentaccount = &delconsignor
				case step.Obj == "delconsignee":
					currentaccount = &delconsignee
				case step.Obj == "delcarrier":
					currentaccount = &delcarrier
				}
				status, resbytes, timelog = createAccount(step.File, *currentaccount)
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
