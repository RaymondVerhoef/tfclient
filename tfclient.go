package main

import (
	"bytes"
	"crypto/sha256"
	b64 "encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"mime"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
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

// Verhoeff
type row [10]int

// multiplication table
type mTable [10]row

var d mTable = mTable{
	row{0, 1, 2, 3, 4, 5, 6, 7, 8, 9},
	row{1, 2, 3, 4, 0, 6, 7, 8, 9, 5},
	row{2, 3, 4, 0, 1, 7, 8, 9, 5, 6},
	row{3, 4, 0, 1, 2, 8, 9, 5, 6, 7},
	row{4, 0, 1, 2, 3, 9, 5, 6, 7, 8},
	row{5, 9, 8, 7, 6, 0, 4, 3, 2, 1},
	row{6, 5, 9, 8, 7, 1, 0, 4, 3, 2},
	row{7, 6, 5, 9, 8, 2, 1, 0, 4, 3},
	row{8, 7, 6, 5, 9, 3, 2, 1, 0, 4},
	row{9, 8, 7, 6, 5, 4, 3, 2, 1, 0},
}

// permutation table
type pTable [8]row

var p pTable = pTable{
	row{0, 1, 2, 3, 4, 5, 6, 7, 8, 9},
	row{1, 5, 7, 6, 2, 8, 3, 0, 9, 4},
	row{5, 8, 0, 3, 7, 9, 6, 1, 4, 2},
	row{8, 9, 1, 6, 0, 4, 3, 5, 2, 7},
	row{9, 4, 5, 3, 1, 2, 6, 8, 7, 0},
	row{4, 2, 8, 6, 5, 7, 3, 9, 0, 1},
	row{2, 7, 9, 3, 8, 0, 6, 4, 1, 5},
	row{7, 0, 4, 6, 9, 1, 3, 2, 5, 8},
}

var inv row = row{0, 4, 3, 2, 1, 5, 6, 7, 8, 9}

// Structs

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
type Order struct {
	Amount              int    `json:"amount"`
	BuildingNumber      string `json:"buildingNumber"`
	CityName            string `json:"cityName"`
	DebtorNumber        string `json:"debtorNumber"`
	Organisation        string `json:"organisation"`
	PhoneNumber         string `json:"phoneNumber"`
	PostalCode          string `json:"postalCode"`
	PurchaseOrderNumber string `json:"purchaseOrderNumber"`
	StreetName          string `json:"streetName"`
}
type Step struct {
	File    string
	Parms   string
	Obj     string
	Action  string
	Url     string
	Asserts string
}
type Assert struct {
	Asserts []struct {
		Status []int `json:"status"`
	} `json:"asserts"`
}
type Build struct {
	Version string `json:"buildVersion"`
}
type ApprovalPostBody struct {
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
type Approval struct {
	Account struct {
		AccountID     string `json:"accountId"`
		AccountNumber string `json:"accountNumber"`
		Email         string `json:"email"`
		Name          string `json:"name"`
		PhoneNumber   string `json:"phoneNumber"`
	} `json:"account"`
	Action               string `json:"action"`
	ApprovalID           string `json:"approvalId"`
	CommitID             string `json:"commitId"`
	CreateDateTimeClient string `json:"createDateTimeClient"`
	CreateDateTimeServer string `json:"createDateTimeServer"`
	Location             struct {
		Latitude  string `json:"latitude"`
		Longitude string `json:"longitude"`
	} `json:"location"`
	Place           string   `json:"place"`
	PreviousCommits []string `json:"previousCommits"`
	Role            string   `json:"role"`
	SubmittedBy     struct {
		AccountID     string `json:"accountId"`
		AccountNumber string `json:"accountNumber"`
		Email         string `json:"email"`
		Name          string `json:"name"`
		PhoneNumber   string `json:"phoneNumber"`
	} `json:"submittedBy"`
	Type string `json:"type"`
}
type Attachment struct {
	AttachmentId     string `json:"attachmentId"`
	Content          string `json:"content"`
	MimeType         string `json:"mimeType",omitempty`
	Name             string `json:"name"`
	OriginalFileName string `json:"originalFileName"`
	Sealed           bool   `json:"sealed"`
	Size             int    `json:"size"`
	Type             string `json:"type"`
}
type CommentPostBody struct {
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
type Comment struct {
	AccountID   string `json:"accountId"`
	Attachments []struct {
		AttachmentID     string `json:"attachmentId"`
		Content          string `json:"content"`
		MimeType         string `json:"mimeType"`
		Name             string `json:"name"`
		OriginalFileName string `json:"originalFileName"`
		Sealed           bool   `json:"sealed"`
		Size             int    `json:"size"`
		Type             string `json:"type"`
	} `json:"attachments"`
	ClientMeta           string   `json:"clientMeta"`
	CommentID            string   `json:"commentId"`
	CommitID             string   `json:"commitId"`
	CreateDateTimeClient string   `json:"createDateTimeClient"`
	CreateDateTimeServer string   `json:"createDateTimeServer"`
	CreatorName          string   `json:"creatorName"`
	CreatorRole          string   `json:"creatorRole"`
	PreviousCommits      []string `json:"previousCommits"`
	Text                 string   `json:"text"`
	Type                 string   `json:"type"`
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
type Secrets struct {
	S1 string `json:"s1"`
	S2 string `json:"s2"`
	S3 string `json:"s3"`
}
type UpdatePostBody struct {
	NewFreightDocumentStatus string   `json:"newFreightDocumentStatus"`
	PreviousCommits          []string `json:"previousCommits"`
	SecondsSinceCreation     int      `json:"secondsSinceCreation"`
}
type Update struct {
	Account struct {
		AccountID     string `json:"accountId"`
		AccountNumber string `json:"accountNumber"`
		Email         string `json:"email"`
		Name          string `json:"name"`
		PhoneNumber   string `json:"phoneNumber"`
	} `json:"account"`
	CommitID                 string        `json:"commitId"`
	CreateDateTimeClient     string        `json:"createDateTimeClient"`
	CreateDateTimeServer     string        `json:"createDateTimeServer"`
	NewFreightDocumentStatus string        `json:"newFreightDocumentStatus"`
	PreviousCommits          []interface{} `json:"previousCommits"`
	StatusUpdateID           string        `json:"statusUpdateId"`
}
type Fd struct {
	AgreedDateOfTakingOver        string          `json:"agreedDateOfTakingOver"`
	Approvals                     []Approval      `json:"approvals"`
	Attachments                   []Attachment    `json:"attachments"`
	Carrier                       Role            `json:"carrier"`
	CarrierCode                   string          `json:"carrierCode"`
	CollectionSecrets             Secrets         `json:"collectionSecrets"`
	Comments                      []Comment       `json:"comments"`
	Consignee                     Role            `json:"consignee"`
	Consignor                     Role            `json:"consignor"`
	DeliveryDate                  string          `json:"deliveryDate"`
	DeliverySecrets               Secrets         `json:"deliverySecrets"`
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

// Enums

var CONSIGNOR_TO_CARRIER = "CONSIGNOR_TO_CARRIER"
var TO_OTHER_CARRIER = "TO_OTHER_CARRIER"
var RECEIVE_FROM_OTHER_CARRIER = "RECEIVE_FROM_OTHER_CARRIER"
var CARRIER_TO_CONSIGNEE = "CARRIER_TO_CONSIGNEE"
var UNKNOWN = "UNKNOWN"

// Globals

var host = ""
var httplog = false
var clientid = ""
var clientsecret = ""
var methods = []string{"POST", "PUT", "PATCH", "DELETE", "HEAD", "GET", "OPTIONS", "TRACE"}
var nobody = []string{"HEAD", "GET", "OPTIONS", "TRACE"}

var build Build
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

func intInSlice(a int, list []int) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}

func stringInSlice(a string, list []string) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}

func leftPad(s string, max int) string {
	len := max - len(s)
	if len > 0 {
		return strings.Repeat("0", len) + s
	} else {
		return s
	}
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

func generateVerhoeff(num string) string {
	ln := len(num)
	c := 0
	for i := 0; i < ln; i++ {
		c = d[c][p[((i + 1) % 8)][int(num[ln-i-1]-'0')]]
	}
	return strconv.Itoa(inv[c])
}

func validateVerhoeff(num string) bool {
	ln := len(num)
	c := 0
	for i := 0; i < ln; i++ {
		c = d[c][p[(i % 8)][int(num[ln-i-1]-'0')]]
	}
	return c == 0
}

func getSecrets(freightDocument *Fd, ttype string) Secrets {

	var secrets Secrets
	switch {
	case ttype == "CONSIGNOR_TO_CARRIER":
		secrets = freightDocument.CollectionSecrets
		break
	case ttype == "TO_OTHER_CARRIER":
	case ttype == "RECEIVE_FROM_OTHER_CARRIER":
	case ttype == "CARRIER_TO_CONSIGNEE":
		secrets = freightDocument.DeliverySecrets
		break
	}
	return secrets
}

func gatherComments(freightDocument *Fd) []string {
	var comments []string
	for i, _ := range freightDocument.Comments {
		comment := freightDocument.Comments[i].Text
		if len(comment) > 0 {
			comments = append(comments, comment)
		}
	}
	return comments
}

func calculateChallengeCode(transfollowNumber string, s1 string, s3 string, contentHash string) string {
	var code string = ""
	if len(s1) == 0 || len(s3) == 0 || len(contentHash) == 0 || len(transfollowNumber) != 12 {
		fmt.Println("Missing transfollowNumber, s1, s3 and/or contentHash")
		return ""
	}
	contentHash = leftPad(contentHash, 5)
	s1 = leftPad(s1, 4)
	s3 = leftPad(s3, 3)
	code = contentHash + transfollowNumber + s1 + s3
	code = code + generateVerhoeff(code)

	if len(code) != 25 {
		fmt.Println("Challenge code isn't 25 digits.")
	}
	return code
}

func calculateResponseCode(accountNumber string, s2 string, MAC string, contentMAC string) string {
	var code string = ""
	if len(s2) == 0 || len(accountNumber) == 0 || len(MAC) == 0 || len(contentMAC) == 0 {
		fmt.Println("Missing accountNumber, s2, MAC and/or contentMAC")
		return ""
	}
	s2 = leftPad(s2, 3)
	accountNumber = leftPad(accountNumber, 8)
	MAC = leftPad(MAC, 8)
	contentMAC = leftPad(contentMAC, 5)

	code = contentMAC + accountNumber + s2 + MAC
	code = code + generateVerhoeff(code)

	if len(code) != 25 {
		fmt.Println("Response code isn't 25 digits.")
	}
	return code
}

func generateMAC(TFN string, secret string, length int) string {

	var blocksizeBits = 512
	var blocksizeBytes = blocksizeBits / 8

	// convert secret to byte array;
	bsecret, err := b64.StdEncoding.DecodeString(secret)
	if err != nil {
		fmt.Println("error:", err)
		return ""
	}

	// secret should be 512 bits; the above should already have ensured this, and this is just here as an extra check
	if len(bsecret) != blocksizeBytes {
		fmt.Printf("Secret size was %d instead of 512\n", len(bsecret)*8)
		return ""
	}

	var opadKey = make([]byte, blocksizeBytes)
	var ipadKey = make([]byte, blocksizeBytes)
	for i := 0; i < blocksizeBytes; i++ {
		opadKey[i] = (0x5c ^ bsecret[i])
		ipadKey[i] = (0x36 ^ bsecret[i])
	}

	ktfn := append(ipadKey, []byte(TFN)...)
	sha1 := sha256.New()
	sha1.Write([]byte(ktfn))

	ksha := append(opadKey, sha1.Sum(nil)...)
	sha2 := sha256.New()
	sha2.Write([]byte(ksha))

	mac := sha2.Sum(nil)
	bigint := new(big.Int).SetBytes(mac)
	tostring := bigint.String()
	return tostring[len(tostring)-length : len(tostring)]
}

func generateContentMAC(contenthash string, transfollownumber string, accountsecret string) string {
	message := contenthash + "|" + transfollownumber
	return generateMAC(message, accountsecret, 5)
}

func generateContentHash(transfollownumber string, ctxt []string) string {
	var content string
	cnt := len(ctxt)
	if cnt > 0 {
		sort.Strings(ctxt)
		for i := 0; i < cnt; i++ {
			content += ctxt[i] + "|"
		}
	}

	content = content + transfollownumber

	if cnt > 9 {
		cnt = 9
	}

	hash := sha256.New()
	hash.Write([]byte(content))
	sum := hash.Sum(nil)
	bigint := new(big.Int).SetBytes(sum)
	tostring := bigint.String()
	withcount := tostring + strconv.Itoa(cnt)
	return withcount[len(withcount)-5 : len(withcount)]
}

func generateChallengeCode(freightDocument *Fd, ttype string) string {
	secrets := getSecrets(freightDocument, ttype)

	if len(secrets.S1) == 0 {
		fmt.Println("User does not have the rights to access S1 for this transfer, meaning he is not the carrier of this document")
		return ""
	}
	if len(secrets.S3) == 0 {
		if ttype == "CONSIGNOR_TO_CARRIER" {
			fmt.Println("User does not have the rights to access S3 for this transfer, meaning he is neither the carrier of this document, nor the consignor")
		} else {
			fmt.Println("User does not have the rights to access S3 for this transfer, meaning he is neither the carrier of this document, nor the consignee")
		}
		return ""
	}

	comments := gatherComments(freightDocument)
	contentHash := generateContentHash(freightDocument.TransFollowNumber, comments)

	return calculateChallengeCode(freightDocument.TransFollowNumber, secrets.S1, secrets.S3, contentHash)
}

func generateResponseCode(freightDocument *Fd, ttype string, challengeCode string) string {
	secrets := getSecrets(freightDocument, ttype)

	if len(secrets.S2) == 0 {
		if ttype == "CONSIGNOR_TO_CARRIER" {
			fmt.Println("User does not have the rights to access S2 for this transfer, meaning he is neither the carrier of this document, nor the consignor")
		} else {
			fmt.Println("User does not have the rights to access S2 for this transfer, meaning he is neither the carrier of this document, nor the consignee")
		}
		return ""
	}

	MAC := generateMAC(freightDocument.TransFollowNumber, currentlogin.AccountSecret, 8)
	contentMAC := generateContentMAC(challengeCode[0:5], freightDocument.TransFollowNumber, currentlogin.AccountSecret)

	return calculateResponseCode(currentlogin.AccountNumber, secrets.S2, MAC, contentMAC)
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
			fmt.Printf("%s: %v\n", k, v)
		}
		reqbodystr := reqbody.Encode()
		if len(reqbodystr) > 0 {
			fmt.Println(" ")
			fmt.Println(reqbodystr)
		}

		fmt.Println("RESPONSE")
		fmt.Println("Status", resp.StatusCode)

		var dat map[string]interface{}
		err := json.Unmarshal(resbytes, &dat)
		check(err)

		response, err := json.MarshalIndent(dat, "", "  ")
		check(err)

		if len(response) > 0 {
			fmt.Println(" ")
			fmt.Println(string(response))
		}

	}
	if status == 200 {
		jsonerr := json.Unmarshal(resbytes, &currentlogin)
		check(jsonerr)
		if refreshtoken == "" {
			url := "/accounts/users/me"
			status, resbytes, _ = callApi("GET", url, "Bearer "+currentlogin.AccessToken, "", 0)
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
	status, resbytes, _ := callApi("GET", url, "", "", 0)
	if status == 200 {
		jsonerr := json.Unmarshal(resbytes, &build)
		check(jsonerr)
	}
	return status == 200
}

func refreshToken() int {
	var account *Account
	return login(*account, currentlogin.RefreshToken)
}

func callApi(method string, url string, auth string, reqbody string, partlog int) (int, []byte, string) {
	var resbody = ""
	var resbytes = []byte(resbody)
	var reqbytes = []byte(reqbody)

	req, err := http.NewRequest(method, "https://"+host+url, bytes.NewBuffer(reqbytes))
	check(err)

	if len(auth) > 0 {
		req.Header.Set("Authorization", auth)
	}
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
		if partlog > 3 {
			fmt.Println("REQUEST")
			fmt.Println(method, req.URL)
			for k, v := range req.Header {
				fmt.Printf("%s: %v\n", k, v)
			}
		}
		if partlog > 2 {
			if len(reqbody) > 0 {
				fmt.Println(" ")
				fmt.Println(reqbody)
			}
		}
		if partlog > 1 {
			fmt.Println("RESPONSE")
			fmt.Println("Status", resp.StatusCode)
		}
		if partlog > 0 {
			//response := resbytes
			var dat map[string]interface{}
			if len(resbytes) > 0 {
				err := json.Unmarshal(resbytes, &dat)
				check(err)

				response, err := json.MarshalIndent(dat, "", "  ")
				check(err)

				fmt.Println(" ")
				fmt.Println(string(response))
			}
		}
	}

	elapsed := time.Since(start)
	timelog := fmt.Sprintf("%s %s in %d ms.", method, url, elapsed/time.Millisecond)

	return resp.StatusCode, resbytes, timelog
}

func doCall(method string, url string, auth string, reqbody string) (int, []byte, string) {
	var errors Errs
	status, resbytes, timelog := callApi(method, url, auth, reqbody, 4)

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
				attachment.MimeType = mime.TypeByExtension(filepath.Ext(attachment.Name))
				attachments = append(attachments, *attachment)
			} else {
				fmt.Println("Could not find", attachment.Name)
			}
		}
	}
	return attachments
}

func isDuplicate(oldid string, new []Attachment) int {
	for j, _ := range new {
		newatt := &new[j]
		if newatt.AttachmentId == oldid {
			return j
		}
	}
	return -1
}

func checkAttachments(old []Attachment, new []Attachment, remove bool) []Attachment {
	var attachments []Attachment
	for i, _ := range old {
		// pointers to slice members prevent copies
		oldatt := &old[i]
		j := isDuplicate(oldatt.AttachmentId, new)
		if j >= 0 {
			newatt := &new[j]
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
			new = append(new[:j], new[j+1:]...)
		} else if remove == false {
			attachments = append(attachments, *oldatt)
		}
	}
	return attachments
}

func removeUnwantedAttributes(reqbody string) string {
	r := regexp.MustCompile(`"submitterAccountId": *(?s)(.*?)\"(.*?)\"`)
	reqbody = r.ReplaceAllString(reqbody, "\"submitterAccountId\":null")
	r = regexp.MustCompile(`"lastModifiedDateTime": *(?s)(.*?)\"(.*?)\"`)
	reqbody = r.ReplaceAllString(reqbody, "\"lastModifiedDateTime\":null")
	r = regexp.MustCompile(`"collectionSecrets": *(?s)(.*?)\{(.*?)\}`)
	reqbody = r.ReplaceAllString(reqbody, "\"collectionSecrets\":null")
	r = regexp.MustCompile(`"deliverySecrets": *(?s)(.*?)\{(.*?)\}`)
	reqbody = r.ReplaceAllString(reqbody, "\"deliverySecrets\":null")
	return reqbody
}

func replacePreviousCommits(reqbody string, previouscommits []string) string {
	if len(previouscommits) > 0 {
		pc, err := json.Marshal(previouscommits)
		check(err)
		r := regexp.MustCompile(`"previousCommits": *(?s)(.*?)\[(.*?)\]`)
		reqbody = r.ReplaceAllString(reqbody, "\"previousCommits\": "+string(pc))
	}
	return reqbody
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
	var currentattid = ""
	var currentfd *Fd = nil
	var currentatt *Attachment = nil
	var previouscommits []string

	var challengecode string
	var responsecode string

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
	makeAccountStruct(cfg, "delegate_consignor", &delconsignor)
	makeAccountStruct(cfg, "delegate_consignee", &delconsignee)

	if isOnline(host) {
		fmt.Println("-----------------------------------------------------------------")
		fmt.Println("Start scenario on", host, build.Version)
		clientid, _ = env.String("client.id")
		clientsecret, _ = env.String("client.secret")

		step_string, err := ioutil.ReadFile(stepfile)
		step_str := strings.TrimSpace(string(step_string))
		check(err)

		stepcfg, err := parseConfigString(step_str)
		steps, _ := stepcfg.Get("steps")
		check(err)
		currentfdid, _ = stepcfg.String("currentfd")
		currentattid, _ = stepcfg.String("currentatt")

	StepLoop:
		for i, stepmap := range steps.Root.([]interface{}) {

			var step Step
			var asserts Assert
			err = fillStruct(stepmap.(map[string]interface{}), &step)
			check(err)
			if len(step.Asserts) > 0 {
				err := json.Unmarshal([]byte(step.Asserts), &asserts)
				check(err)
			}

			switch {
			case step.Action == "break":
				break StepLoop

			case step.Action == "genericget":

				fmt.Println("-----------------------------------------------------------------")
				fmt.Println("Step", i+1)
				fmt.Printf("GET %s with file %s (parms %s subj %s)\n", step.Url, step.File, step.Parms, step.Obj)
				fmt.Println("-----------------------------------------------------------------")

				if len(currentlogin.AccessToken) > 0 {
					status, resbytes, timelog = doCall("GET", step.Url, "Bearer "+currentlogin.AccessToken, "")
				} else {
					status, resbytes, timelog = doCall("GET", step.Url, "", "")
				}
				log.Printf("%s with status %d", timelog, status)

			case step.Action == "validateemailtoken":
				if len(step.Parms) > 0 {
					step.Url = strings.Replace(step.Url, "{{token}}", step.Parms, 1)
				}
				fmt.Println("-----------------------------------------------------------------")
				fmt.Println("Step", i+1)
				fmt.Printf("GET %s with file %s (parms %s subj %s)\n", step.Url, step.File, step.Parms, step.Obj)
				fmt.Println("-----------------------------------------------------------------")

				if len(step.Parms) > 0 {
					status, resbytes, timelog = doCall("GET", step.Url, "", "")

					log.Printf("%s with status %d", timelog, status)
					fmt.Printf("%s\n", timelog)
				} else {
					fmt.Println("email token missing")
				}

			case step.Action == "getfd":
				if len(currentfdid) > 0 {
					step.Url = strings.Replace(step.Url, "{{id}}", currentfdid, 1)
				}
				fmt.Println("-----------------------------------------------------------------")
				fmt.Println("Step", i+1)
				fmt.Printf("GET %s \n", step.Url)
				fmt.Println("-----------------------------------------------------------------")
				if len(currentfdid) > 0 {
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
					fmt.Printf("%s\n", timelog)
				} else {
					fmt.Println("freightDocumentId missing")
				}

			case step.Action == "getfdatt" || step.Action == "getatt":
				if len(currentfdid) > 0 {
					step.Url = strings.Replace(step.Url, "{{fdid}}", currentfdid, 1)
				}
				if len(currentattid) > 0 {
					step.Url = strings.Replace(step.Url, "{{atid}}", currentattid, 1)
				}
				fmt.Println("-----------------------------------------------------------------")
				fmt.Println("Step", i+1)
				fmt.Printf("GET %s \n", step.Url)
				fmt.Println("-----------------------------------------------------------------")
				if len(currentfdid) > 0 && len(currentattid) > 0 {
					status, resbytes, timelog = doCall("GET", step.Url, "Bearer "+currentlogin.AccessToken, "")
					if status == 200 {
						jsonerr := json.Unmarshal(resbytes, &currentatt)
						check(jsonerr)
						currentattid = currentatt.AttachmentId

						fmt.Printf("FD %s with Att %s\n", currentfdid, currentattid)
					}
					log.Printf("%s with status %d", timelog, status)
					fmt.Printf("%s\n", timelog)
				} else {
					fmt.Println("freightDocumentId and/or attachmentId missing")
				}

			case step.Action == "getfdresponsecode":
				if len(currentfdid) > 0 {
					step.Url = strings.Replace(step.Url, "{{id}}", currentfdid, 1)
				}
				if len(step.Obj) > 0 {
					step.Url = strings.Replace(step.Url, "{{transfertype}}", step.Obj, 1)
				}
				fmt.Println("-----------------------------------------------------------------")
				fmt.Println("Step", i+1)
				fmt.Printf("GET %s \n", step.Url)
				fmt.Println("-----------------------------------------------------------------")
				if len(currentfdid) > 0 && len(step.Obj) > 0 {
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
				} else {
					fmt.Println("freightDocumentId and/or Obj transfertype missing")
					break StepLoop
				}

			case step.Action == "issuefd":
				if len(currentfdid) > 0 {
					step.Url = strings.Replace(step.Url, "{{id}}", currentfdid, 1)
				}
				fmt.Println("-----------------------------------------------------------------")
				fmt.Println("Step", i+1)
				fmt.Printf("POST %s \n", step.Url)
				fmt.Println("-----------------------------------------------------------------")
				if len(currentfdid) > 0 {
					status, resbytes, timelog = doCall("POST", step.Url, "Bearer "+currentlogin.AccessToken, "")
					log.Printf("%s with status %d", timelog, status)
					fmt.Printf("%s\n", timelog)
				} else {
					fmt.Println("freightDocumentId is missing")
					break StepLoop
				}

			case step.Action == "createfd":
				fmt.Println("-----------------------------------------------------------------")
				fmt.Println("Step", i+1)
				fmt.Printf("POST %s with file %s (parms %s subj %s)\n", step.Url, step.File, step.Parms, step.Obj)
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
					check(jsonerr)
				}

				if currentfd != nil {

					if len(step.Parms) > 0 {
						parmsattachments := makeNewAttachments(step.Parms)
						currentfd.Attachments = append(currentfd.Attachments, parmsattachments...)
					}

					newfdjson, _ := json.MarshalIndent(currentfd, "", "  ")
					reqbody := removeUnwantedAttributes(string(newfdjson))

					status, resbytes, timelog = doCall("POST", step.Url, "Bearer "+currentlogin.AccessToken, reqbody)
					if status == 201 {
						result, err := config.ParseJson(string(resbytes))
						check(err)
						currentfdid, err = result.String("freightDocumentId")
						check(err)
						if len(currentfdid) > 0 {
							fmt.Printf("new FD at https://%s/#home,viewFreightDocument&id=%s\n", portal, currentfdid)
						}
					}
					log.Printf("%s with status %d", timelog, status)
					fmt.Printf("%s\n", timelog)
				} else {
					fmt.Println("New freightDocument content is missing")
					break StepLoop
				}

			case step.Action == "updatefd":
				var oldattachments []Attachment
				var newattachments []Attachment

				step.Url = strings.Replace(step.Url, "{{id}}", currentfdid, 1)
				oldattachments = currentfd.Attachments

				fmt.Println("-----------------------------------------------------------------")
				fmt.Println("Step", i+1)
				fmt.Printf("PUT %s with file %s (parms %s subj %s)\n", step.Url, step.File, step.Parms, step.Obj)
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
					oldattachments = checkAttachments(oldattachments, currentfd.Attachments, true)
					check(jsonerr)
				}

				if currentfd != nil {

					if len(step.Parms) > 0 {
						newattachments = makeNewAttachments(step.Parms)
					}
					currentfd.Attachments = checkAttachments(oldattachments, newattachments, false)
					currentfd.Attachments = append(currentfd.Attachments, newattachments...)

					newfdjson, _ := json.MarshalIndent(currentfd, "", "  ")
					reqbody := removeUnwantedAttributes(string(newfdjson))
					reqbody = replacePreviousCommits(reqbody, previouscommits)

					status, resbytes, timelog = doCall("PUT", step.Url, "Bearer "+currentlogin.AccessToken, reqbody)
					if status == 205 {
						if len(currentfdid) > 0 {
							fmt.Printf("changed FD at https://%s/#home,viewFreightDocument&id=%s\n", portal, currentfdid)
						}
					}
					log.Printf("%s with status %d", timelog, status)
					fmt.Printf("%s\n", timelog)
				} else {
					fmt.Println("Updated freightDocument content is missing")
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
					fmt.Printf("%s\n", timelog)
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
					reqbody = replacePreviousCommits(reqbody, previouscommits)

					if len(step.Parms) > 0 {
						attachments = makeNewAttachments(step.Parms)
						if len(attachments) > 0 {
							att, err := json.MarshalIndent(attachments, "", "  ")
							check(err)
							r := regexp.MustCompile(`"attachments": *(?s)(.*?)\[(.*?)\]`)
							reqbody = r.ReplaceAllString(reqbody, "\"attachments\": "+string(att))
						}
					}
					status, resbytes, timelog = doCall("POST", step.Url, "Bearer "+currentlogin.AccessToken, reqbody)

					log.Printf("%s with status %d", timelog, status)
					fmt.Printf("%s\n", timelog)
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
					if len(step.Parms) > 0 && len(step.Obj) > 0 {
						template, err := ioutil.ReadFile(step.File)
						check(err)
						reqbody := strings.TrimSpace(string(template))
						reqbody = strings.Replace(reqbody, "{{ownrole}}", step.Parms, 1)
						reqbody = strings.Replace(reqbody, "{{transfer}}", step.Obj, 1)
						reqbody = replacePreviousCommits(reqbody, previouscommits)

						status, resbytes, timelog = doCall("POST", step.Url, "Bearer "+currentlogin.AccessToken, reqbody)

						log.Printf("%s with status %d", timelog, status)
						fmt.Printf("%s\n", timelog)
					} else {
						fmt.Println("Parms role and/or Obj transfer missing")
					}
				} else {
					fmt.Println("freightDocumentId is missing")
					break StepLoop
				}

			case step.Action == "generatechallengecode":

				fmt.Println("-----------------------------------------------------------------")
				fmt.Println("Step", i+1)
				fmt.Printf("Generate challengecode(parms %s)\n", step.Parms)
				fmt.Println("-----------------------------------------------------------------")

				challengecode = generateChallengeCode(currentfd, step.Parms)

				fmt.Println("Challengecode:", challengecode)

			case step.Action == "generateresponsecode":

				fmt.Println("-----------------------------------------------------------------")
				fmt.Println("Step", i+1)
				fmt.Printf("Generate responsecode(parms %s)\n", step.Parms)
				fmt.Println("-----------------------------------------------------------------")

				responsecode = generateResponseCode(currentfd, step.Parms, challengecode)

				fmt.Println("Responsecode:", responsecode)

			case step.Action == "submitcounterpartyapprovaltfa":
				if len(currentfdid) > 0 {
					step.Url = strings.Replace(step.Url, "{{id}}", currentfdid, 1)
				}
				fmt.Println("-----------------------------------------------------------------")
				fmt.Println("Step", i+1)
				fmt.Printf("POST %s with file %s (parms %s subj %s)\n", step.Url, step.File, step.Parms, step.Obj)
				fmt.Println("-----------------------------------------------------------------")

				if len(currentfdid) > 0 {
					if len(step.Obj) > 0 {
						template, err := ioutil.ReadFile(step.File)
						check(err)
						reqbody := strings.TrimSpace(string(template))

						reqbody = strings.Replace(reqbody, "{{responsecode}}", responsecode, 1)
						reqbody = strings.Replace(reqbody, "{{transfer}}", step.Obj, 1)
						reqbody = replacePreviousCommits(reqbody, previouscommits)

						status, resbytes, timelog = doCall("POST", step.Url, "Bearer "+currentlogin.AccessToken, reqbody)

						log.Printf("%s with status %d", timelog, status)
						fmt.Printf("%s\n", timelog)
					} else {
						fmt.Println("Obj transfer missing")
					}
				} else {
					fmt.Println("freightDocumentId is missing")
					break StepLoop
				}

			case step.Action == "submitcounterpartyapprovalsog":
				var attachments []Attachment
				if len(currentfdid) > 0 {
					step.Url = strings.Replace(step.Url, "{{id}}", currentfdid, 1)
				}
				fmt.Println("-----------------------------------------------------------------")
				fmt.Println("Step", i+1)
				fmt.Printf("POST %s with file %s (parms %s subj %s)\n", step.Url, step.File, step.Parms, step.Obj)
				fmt.Println("-----------------------------------------------------------------")

				if len(currentfdid) > 0 {
					if len(step.Parms) > 0 && len(step.Obj) > 0 {
						template, err := ioutil.ReadFile(step.File)
						check(err)
						reqbody := strings.TrimSpace(string(template))

						reqbody = strings.Replace(reqbody, "{{transfer}}", step.Obj, 1)
						reqbody = replacePreviousCommits(reqbody, previouscommits)

						attachments = makeNewAttachments(step.Parms)
						if len(attachments) > 0 {
							att, err := json.Marshal(attachments)
							check(err)
							atts := strings.Replace(string(att), ",\"type\":\"SIGNONGLASS\"", "", 1)
							atts = strings.Replace(string(att), ",\"type\":\"\"", "", 1)
							atts = strings.Replace(atts, ",\"sealed\":true", "", 1)
							atts = strings.Replace(atts, ",\"sealed\":false", "", 1)
							atts = strings.Replace(atts, ",\"size\":0", "", 1)
							r := regexp.MustCompile(`"attachments": *(?s)(.*?)\[(.*?)\]`)
							reqbody = r.ReplaceAllString(reqbody, "\"attachments\": "+atts)
						}

						status, resbytes, timelog = doCall("POST", step.Url, "Bearer "+currentlogin.AccessToken, reqbody)

						log.Printf("%s with status %d", timelog, status)
						fmt.Printf("%s\n", timelog)
					} else {
						fmt.Println("Parms image file and/or Obj transfer missing")
					}
				} else {
					fmt.Println("freightDocumentId is missing")
					break StepLoop
				}

			case step.Action == "submitproofoftransfer":
				if len(currentfdid) > 0 {
					step.Url = strings.Replace(step.Url, "{{id}}", currentfdid, 1)
				}
				fmt.Println("-----------------------------------------------------------------")
				fmt.Println("Step", i+1)
				fmt.Printf("POST %s with file %s\n", step.Url, step.File)
				fmt.Println("-----------------------------------------------------------------")

				if len(currentfdid) > 0 {
					template, err := ioutil.ReadFile(step.File)
					check(err)
					reqbody := strings.TrimSpace(string(template))
					reqbody = strings.Replace(reqbody, "{{proof}}", challengecode[len(challengecode)-8:len(challengecode)-4], 1)
					status, resbytes, timelog = doCall("POST", step.Url, "Bearer "+currentlogin.AccessToken, reqbody)

					log.Printf("%s with status %d", timelog, status)
					fmt.Printf("%s\n", timelog)
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
					if len(step.Obj) > 0 {
						template, err := ioutil.ReadFile(step.File)
						check(err)
						reqbody := strings.TrimSpace(string(template))

						reqbody = strings.Replace(reqbody, "{{newstatus}}", step.Obj, 1)
						reqbody = replacePreviousCommits(reqbody, previouscommits)

						status, resbytes, timelog = doCall("POST", step.Url, "Bearer "+currentlogin.AccessToken, reqbody)

						log.Printf("%s with status %d", timelog, status)
						fmt.Printf("%s\n", timelog)
					} else {
						fmt.Println("Obj newstatus missing")
					}
				} else {
					fmt.Println("freightDocumentId is missing")
					break StepLoop
				}

			case step.Action == "validatecode":
				if len(currentfdid) > 0 {
					step.Url = strings.Replace(step.Url, "{{id}}", currentfdid, 1)
				}
				fmt.Println("-----------------------------------------------------------------")
				fmt.Println("Step", i+1)
				fmt.Printf("POST %s with file %s (parms %s subj %s)\n", step.Url, step.File, step.Parms, step.Obj)
				fmt.Println("-----------------------------------------------------------------")

				template, err := ioutil.ReadFile(step.File)
				check(err)
				reqbody := strings.TrimSpace(string(template))
				reqbody = strings.Replace(reqbody, "{{type}}", step.Obj, 1)
				if step.Parms == "CHALLENGE" {
					reqbody = strings.Replace(reqbody, "{{code}}", challengecode, 1)
				} else {
					reqbody = strings.Replace(reqbody, "{{code}}", responsecode, 1)
				}

				if len(currentlogin.AccessToken) > 0 {
					status, resbytes, timelog = doCall("POST", step.Url, "Bearer "+currentlogin.AccessToken, reqbody)
				}
				log.Printf("%s with status %d", timelog, status)
				fmt.Printf("%s\n", timelog)

			case step.Action == "genericpost":

				fmt.Println("-----------------------------------------------------------------")
				fmt.Println("Step", i+1)
				fmt.Printf("POST %s with file %s (parms %s subj %s)\n", step.Url, step.File, step.Parms, step.Obj)
				fmt.Println("-----------------------------------------------------------------")

				template, err := ioutil.ReadFile(step.File)
				check(err)
				reqbody := strings.TrimSpace(string(template))
				if len(currentlogin.AccessToken) > 0 {
					status, resbytes, timelog = doCall("POST", step.Url, "Bearer "+currentlogin.AccessToken, reqbody)
				} else {
					status, resbytes, timelog = doCall("POST", step.Url, "", reqbody)
				}
				log.Printf("%s with status %d", timelog, status)
				fmt.Printf("%s\n", timelog)

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
					fmt.Println("No credentials found in config to log in with")
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
				fmt.Printf("%s\n", timelog)

			default:
				fmt.Println("-----------------------------------------------------------------")
				fmt.Println("Step", i+1)
				fmt.Printf("Unknown action %s\n", step.Action)
				fmt.Println("-----------------------------------------------------------------")
			}

			if len(asserts.Asserts) > 0 {
				if false == intInSlice(status, asserts.Asserts[0].Status) {
					fmt.Printf("Assert status %v failed: %d\n", asserts.Asserts[0].Status, status)
					break StepLoop
				}
			}

		}
		fmt.Println("-----------------------------------------------------------------")
		fmt.Println("End scenario")
		fmt.Println("-----------------------------------------------------------------")

	} else {
		fmt.Println("Offline host:", host)
	}
}
