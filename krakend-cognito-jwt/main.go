package main

import (
	"context"
	"fmt"
	"net/http"
	"strings"	
	"slices"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cognitoidentityprovider"
)

// pluginName is the plugin name
var pluginName = "krakend-cognito-jwt"

// HandlerRegisterer is the symbol the plugin loader will try to load. It must implement the Registerer interface
var HandlerRegisterer = registerer(pluginName)

type registerer string

func (r registerer) RegisterHandlers(f func(
	name string,
	handler func(context.Context, map[string]interface{}, http.Handler) (http.Handler, error),
)) {
	f(string(r), r.registerHandlers)
}

func (r registerer) registerHandlers(_ context.Context, extra map[string]interface{}, h http.Handler) (http.Handler, error) {
	// Log plugin initialization
	logger.Debug(fmt.Sprintf("[PLUGIN: %s] Plugin initialized", pluginName))

	// Return the custom handler
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		config, _ := extra[pluginName].(map[string]interface{})
	
		pathsInterface, _ := config["applicable-endpoints"].([]interface{})
		loginUrl, _ := config["login-url"].(string)
		
		var applicableEndpoints []string
		for _, path := range pathsInterface {
			endpoint, ok := path.(string)
			if !ok {
				logger.Error("An element in 'applicable-endpoints' is not a string")
				return
			}
			applicableEndpoints  = append(applicableEndpoints, endpoint)
		}
		
		if !slices.Contains(applicableEndpoints, req.URL.Path) {
			h.ServeHTTP(w, req)
			return
		}
		

		// Extract the JWT token from the Authorization header
		token := extractToken(req)
		if token == "" {
			logger.Error("Unauthorized: Missing token")
			// add the login URL to the response headers
			w.Header().Set("Access-Control-Expose-Headers", "login-url")
			w.Header().Set("login-url", loginUrl)
			http.Error(w, "Unauthorized: Missing token", http.StatusUnauthorized)
			return
		}

		// Validate the JWT token using AWS Cognito
		valid, err := validateCognitoJWT(token)
		if err != nil {
			logger.Error(fmt.Sprintf("Error validating token: %v", err))
			// add the login URL to the response headers
			w.Header().Set("Access-Control-Expose-Headers", "login-url")
			w.Header().Set("login-url", loginUrl)
			http.Error(w, "Unauthorized: Invalid token", http.StatusUnauthorized)
			return
		}

		if !valid {
			// add the login URL to the response headers
			w.Header().Set("Access-Control-Expose-Headers", "login-url")
			w.Header().Set("login-url", loginUrl)
			http.Error(w, "Unauthorized: Invalid token", http.StatusUnauthorized)
			return
		}
		
		// Get user details from Cognito
		user, err := getUserDetails(token)
		if err != nil {
			logger.Error(fmt.Sprintf("Error getting user details: %v", err))
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		// Extract the email from the user attributes
		email := extractEmailFromUserAttributes(user.UserAttributes)
		if email == "" {
			logger.Error("Email not found in user attributes")
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		
		// Add the email to the request headers
		req.Header.Add("Todo-User-Email", email)
		
		logger.Debug(fmt.Sprintf("[PLUGIN: %s] Forwarding request to backend: %s", pluginName, req.URL.Path))
		logger.Debug(fmt.Sprintf("[PLUGIN: %s] Request headers: %v", pluginName, req.Header))

		// Token is valid, proceed to the next handler (backend)
		h.ServeHTTP(w, req)
	}), nil
}

// extractToken extracts the JWT token from the Authorization header
func extractToken(req *http.Request) string {
	authHeader := req.Header.Get("Authorization")
	if authHeader == "" {
		return ""
	}
	return strings.TrimPrefix(authHeader, "Bearer ")
}

// validateCognitoJWT validates the JWT token using AWS Cognito
func validateCognitoJWT(token string) (bool, error) {
	// Initialize AWS session
	sess, err := session.NewSession(&aws.Config{
		Region: aws.String("us-east-1"), // Replace with your AWS region
	})
	if err != nil {
		return false, err
	}

	// Create Cognito Identity Provider client
	svc := cognitoidentityprovider.New(sess)

	// Validate the token
	input := &cognitoidentityprovider.GetUserInput{
		AccessToken: aws.String(token),
	}

	_, err = svc.GetUser(input)
	if err != nil {
		return false, err
	}

	return true, nil
}

// getUserDetails retrieves user details from Cognito
func getUserDetails(token string) (*cognitoidentityprovider.GetUserOutput, error) {
	sess, err := session.NewSession(&aws.Config{
		Region: aws.String("us-east-1"), // Replace with your AWS region
	})
	if err != nil {
		return nil, err
	}

	svc := cognitoidentityprovider.New(sess)

	input := &cognitoidentityprovider.GetUserInput{
		AccessToken: aws.String(token),
	}

	return svc.GetUser(input)
}

// extractEmailFromUserAttributes extracts the email from the user attributes
func extractEmailFromUserAttributes(attributes []*cognitoidentityprovider.AttributeType) string {
	for _, attr := range attributes {
		if *attr.Name == "email" {
			return *attr.Value
		}
	}
	return ""
}

func main() {}

// This logger is replaced by the RegisterLogger method to load the one from KrakenD
var logger Logger = noopLogger{}

func (registerer) RegisterLogger(v interface{}) {
	l, ok := v.(Logger)
	if !ok {
		return
	}
	logger = l
	logger.Debug(fmt.Sprintf("[PLUGIN: %s] Logger loaded", HandlerRegisterer))
}

type Logger interface {
	Debug(v ...interface{})
	Info(v ...interface{})
	Warning(v ...interface{})
	Error(v ...interface{})
	Critical(v ...interface{})
	Fatal(v ...interface{})
}

// Empty logger implementation
type noopLogger struct{}

func (n noopLogger) Debug(_ ...interface{})    {}
func (n noopLogger) Info(_ ...interface{})     {}
func (n noopLogger) Warning(_ ...interface{})  {}
func (n noopLogger) Error(_ ...interface{})    {}
func (n noopLogger) Critical(_ ...interface{}) {}
func (n noopLogger) Fatal(_ ...interface{})    {}