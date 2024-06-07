package main

import (
	//"encoding/json"
	"fmt"
	"github.com/gorilla/mux"
	"html/template"
	//"io/ioutil"
	"errors"
	"github.com/devkaare/db2"
	"github.com/google/uuid"
	"log"
	"net/http"
	"path"
	"time"
)

var (
	blogKey    = "Blogs"
	userKey    = "Users"
	sessionKey = "Sessions"
)

func CreateBlog(title, description string) map[string]interface{} {
	return map[string]interface{}{
		"Id":          uuid.New().String(),
		"Title":       title,
		"Description": description,
	}
}

func CreateUser(username, email, password string) map[string]interface{} {
	return map[string]interface{}{
		"Id":       uuid.New().String(),
		"Username": username,
		"Email":    email,
		"Password": password,
		"Admin":    false,
	}
}

func CreateSessionId(username string) (map[string]interface{}, string, time.Time) {
	id := uuid.New().String()
	expiryDate := time.Now().Add(180 * 24 * time.Hour)

	user := map[string]interface{}{
		"Id":       id,
		"Username": username,
		"Expires":  expiryDate,
	}

	return user, id, expiryDate
}

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
	return userSession["Id"] == sessionId
}

func UploadBlog(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		fp := path.Join("public", "blog/upload.html")
		tmpl, err := template.ParseFiles(fp)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		if err := tmpl.Execute(w, nil); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	} else if r.Method == "POST" {
		title := r.PostFormValue("title")
		description := r.PostFormValue("description")

		// Save blog to database (cache)
		blog := CreateBlog(title, description)
		db.AddToCache(blogKey, blog)
		db.SaveCache()

		fmt.Fprintf(w, "Received blog post with Title: %s and Description: %s", title, description)
	}
}

func ShowBlogById(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	blog := db.SearchCache(blogKey, "Id", id)
	//log.Println(blog)

	fp := path.Join("public", "blog/blog.html")
	tmpl, err := template.ParseFiles(fp)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if err := tmpl.Execute(w, blog); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func ShowAllBlogs(w http.ResponseWriter, r *http.Request) {
	// Get all blogs from cache
	blogs := db.GetCache(blogKey)
	//for _, blog := range blogs {
	//fmt.Println(blog)
	//}
	fp := path.Join("public", "blog/blogs.html")
	tmpl, err := template.ParseFiles(fp)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if err := tmpl.Execute(w, blogs); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func LogIn(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		fp := path.Join("public", "auth/log-in.html")
		tmpl, err := template.ParseFiles(fp)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		if err := tmpl.Execute(w, nil); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	} else if r.Method == "POST" {
		username := r.PostFormValue("username")
		email := r.PostFormValue("email")
		password := r.PostFormValue("password")

		// Validate input
		if user := ValidateUser(username, email, password); user {
			userSession, sessionId, expiryDate := CreateSessionId(username)
			db.AddToCache(sessionKey, userSession)
			db.SaveCache()

			http.SetCookie(w, &http.Cookie{
				Name:    "session-token",
				Value:   sessionId,
				Expires: expiryDate,
			})

			fmt.Fprintf(w, "Valid")
			return
		}

		fmt.Fprintf(w, "Invalid credentials, refresh this page and retry!")
	}
}

func SignUp(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		fp := path.Join("public", "auth/sign-up.html")
		tmpl, err := template.ParseFiles(fp)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		if err := tmpl.Execute(w, nil); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	} else if r.Method == "POST" {
		username := r.PostFormValue("username")
		email := r.PostFormValue("email")
		password := r.PostFormValue("password")

		// Save blog to database (cache)
		user := CreateUser(username, email, password)
		db.AddToCache(userKey, user)
		db.SaveCache()

		fmt.Fprintf(w, "Received user with Username: %s, Email: %s and Password: %s", username, email, password)
	}
}

func GetCookie(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session-token")
	if err != nil {
		switch {
		case errors.Is(err, http.ErrNoCookie):
			http.Error(w, "Cookie not found", http.StatusBadRequest)
		default:
			log.Println(err)
			http.Error(w, "Server error", http.StatusInternalServerError)
		}
		return
	}

	result := ValidateSessionId(cookie.Value)
	if !result {
		w.Write([]byte("Cookie is invalid"))
		return
	}

	w.Write([]byte("Cookie is valid"))
}

func AdminCheck(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session-token")
	if err != nil {
		switch {
		case errors.Is(err, http.ErrNoCookie):
			http.Error(w, "Cookie not found", http.StatusBadRequest)
		default:
			log.Println(err)
			http.Error(w, "Server error", http.StatusInternalServerError)
		}
		return
	}

	sessionId := cookie.Value
	userSession := db.SearchCache(sessionKey, "Id", sessionId)
	if userSession["Id"] != sessionId {
		w.Write([]byte("Cookie is invalid"))
		return
	}

	user := db.SearchCache(userKey, "Username", userSession["Username"])
	adminPermissionRes := user["Admin"]
	if adminPermissionRes != true {
		w.Write([]byte("Invalid permissions"))
		return
	}

	w.Write([]byte("User has admin permissions!"))
}

func main() {
	db.LoadCache("blogs.json")
	r := mux.NewRouter()

	// Blog handlers
	r.HandleFunc("/blog/upload", UploadBlog)
	r.HandleFunc("/blog/all", ShowAllBlogs)
	r.HandleFunc("/blog/{id}", ShowBlogById)

	// Account auth handlers
	r.HandleFunc("/auth/sign-up", SignUp)
	r.HandleFunc("/auth/log-in", LogIn)
	r.HandleFunc("/auth/test", GetCookie)
	r.HandleFunc("/auth/admin-dash", AdminCheck)

	// TODO: Support ticket handlers

	log.Println("Server started on port 3000")
	log.Fatal(http.ListenAndServe(":3000", r))
}
