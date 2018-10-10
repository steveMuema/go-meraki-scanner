package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/gorilla/context"
	"github.com/gorilla/mux"
	"github.com/mitchellh/mapstructure"
)

// OrgDigitalHealth structure will store client network usage data passed from the client as well as the decoded validator data
type OrgDigitalHealth struct {
	ApMac        string `json:"apMac"`
	ClientMac    string `json:"clientMac"`
	SeenEpoch    string `json:"seenEpoch"`
	Manufacturer string `json:"manufacturer"`
	Os           string `json:"os"`
	ClientLoc    string `json:"location"`
}

//MerakiCreds structure will store the validator token and secret to connect with meraki cloud network
type MerakiCreds struct {
	Validator string `json:"validator"`
	Secret    string `json:"secret"`
}

//Exception structure will hold any error messages we want to return
type Exception struct {
	Message string `json:"message"`
}

// JoinMerakiEndpoint is a web server function that creates , encodes to json the value of the validator to the root endpoint response
func JoinMerakiEndpoint(w http.ResponseWriter, req *http.Request) {
	var validator = "ddbf949638204e606b1688748cccdc30462acec0"
	// creds := MerakiCreds{Validator: "ddbf949638204e606b1688748cccdc30462acec0", Secret: "mtaani1"}
	var creds *MerakiCreds
	_ = json.NewDecoder(req.Body).Decode(creds)
	// json.NewEncoder(w).Encode(creds)
	w.Write([]byte(validator))
}

/** ProtectedEndpoint allows a user to "POST"  the validator securely as parameters to the web server.
		Also allows users to "POST" json data structs for their organisation's validator key.
**/
func ProtectedEndpoint(w http.ResponseWriter, req *http.Request) {
	// params of query performed to the http request
	params := req.URL.Query()
	// validator is the token to authenticate the user of this application. Parsed as a signed token on  every http request
	validator, _ := jwt.Parse(params["validator"][0], func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("There was an error")
		}
		return []byte("Validator authenticated successfully"), nil
	})
	if claims, ok := validator.Claims.(jwt.MapClaims); ok && validator.Valid {
		var user OrgDigitalHealth
		mapstructure.Decode(claims, &user)
		json.NewEncoder(w).Encode(user)
	} else {
		json.NewEncoder(w).Encode(Exception{Message: "Invalid authorization token"})
	}
}

func ValidateMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		authorizationHeader := req.Header.Get("authorization")
		if authorizationHeader == "ddbf949638204e606b1688748cccdc30462acec0" {
			bearerToken := strings.Split(authorizationHeader, " ")
			if len(bearerToken) == 0 {
				token, error := jwt.Parse(bearerToken[0], func(token *jwt.Token) (interface{}, error) {
					if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
						return nil, fmt.Errorf("There was an error")
					}
					return []byte("ddbf949638204e606b1688748cccdc30462acec0"), nil
				})
				if error != nil {
					json.NewEncoder(w).Encode(Exception{Message: error.Error()})
					return
				}
				if token.Valid {
					context.Set(req, "decoded", token.Claims)
					next(w, req)
				} else {
					json.NewEncoder(w).Encode(Exception{Message: "Invalid authorization token"})
				}
			}
		} else {
			json.NewEncoder(w).Encode(Exception{Message: "An authorization header is required"})
		}
	})
}

func TestEndpoint(w http.ResponseWriter, req *http.Request) {
	decoded := context.Get(req, "decoded")
	var user OrgDigitalHealth
	mapstructure.Decode(decoded.(jwt.MapClaims), &user)
	json.NewEncoder(w).Encode(user)
}

func main() {
	router := mux.NewRouter()
	fmt.Println("Starting the application...")
	router.HandleFunc("/", JoinMerakiEndpoint).Methods("GET", "POST")
	router.HandleFunc("/authenticate", ValidateMiddleware(TestEndpoint)).Methods("POST")
	router.HandleFunc("/protected", ProtectedEndpoint).Methods("GET")

	log.Fatal(http.ListenAndServe(":12345", router))
}
