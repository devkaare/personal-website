package main

import (
    "github.com/devkaare/db2"
    "html/template"
    "net/http"
    "errors"
    "log"
)

// User related functions
func ValidateUser(username, email, password string) bool {
	if user := db.SearchCache(userKey, "Username", username); user != nil {
		return user["Password"] == password
	} else if user := db.SearchCache(userKey, "Email", email); user != nil {
		return user["Password"] == password
	}
	return false
}

func ValidateSessionId(sessionId string) bool {
	userSession := db.SearchCache(sessionKey, "Id", sessionId)
	if userSession == nil {
		return false
	}
	if userSession["Id"] == sessionId {
		return true
	}
	return false
}

func ValidateAdminStatus(sessionId string) bool {
	userSession := db.SearchCache(sessionKey, "Id", sessionId)
	if userSession == nil || userSession["Id"] != sessionId {
		return false
	}

	user := db.SearchCache(userKey, "Username", userSession["Username"])
	if user == nil {
		return false
	}
	adminPermissionRes := user["Admin"]

	return adminPermissionRes == true
}

func GetSessionCookie(r *http.Request) (string, error) {
	cookie, err := r.Cookie("session-token")
	if err != nil {
		if errors.Is(err, http.ErrNoCookie) {
			return "", errors.New("cookie not found")
		} else {
			log.Println(err)
			return "", errors.New("server error")
		}
	}

	if result := ValidateSessionId(cookie.Value); !result {
		return "", errors.New("cookie is invalid")
	}

	return cookie.Value, nil
}

func GetUserSession(sessionId string) (map[string]interface{}, error) {
	userSession := db.SearchCache(sessionKey, "Id", sessionId)
	if userSession == nil || userSession["Id"] != sessionId {
		return nil, errors.New("invalid session")
	}

	return userSession, nil
}

// Template related functions
func ExecuteTemplate(w http.ResponseWriter, fp string, data interface{}) {
	tmpl, err := template.ParseFiles(fp)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if err := tmpl.Execute(w, data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
