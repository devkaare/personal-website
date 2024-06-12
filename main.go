package main

import (
	"errors"
	"github.com/devkaare/db2"
	"github.com/gorilla/mux"
	"log"
	"net/http"
	"path"
	"time"
)

var (
	blogKey    = "Blogs"
	userKey    = "Users"
	sessionKey = "Sessions"
	inquiryKey = "Inquiries"
	replyKey   = "Replies"
)

// Blog handlers
func ShowAllBlogsHandler(w http.ResponseWriter, r *http.Request) {
	blogs := db.GetCache(blogKey)
	ExecuteTemplate(w, path.Join("public", "blog/blogs.html"), blogs)
}

func ShowBlogByIdHandler(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	blog := db.SearchCache(blogKey, "Id", id)
	ExecuteTemplate(w, path.Join("public", "blog/blog.html"), blog)
}

func UploadBlogHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		ExecuteTemplate(w, path.Join("public", "blog/upload.html"), nil)
	} else if r.Method == "POST" {
		sessionId, err := GetSessionCookie(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		if result := ValidateAdminStatus(sessionId); !result {
			w.Write([]byte("Invalid permissions"))
			return
		}

		title := r.PostFormValue("title")
		description := r.PostFormValue("description")

		blog := CreateBlog(title, description)
		db.AddToCache(blogKey, blog)
		db.SaveCache()

		w.Header().Add("HX-Redirect", "/blog/all")
	}
}

// Account authentication handlers
func LogInHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		ExecuteTemplate(w, path.Join("public", "auth/log-in.html"), nil)
	} else if r.Method == "POST" {
		username := r.PostFormValue("username")
		email := r.PostFormValue("email")
		password := r.PostFormValue("password")

		if user := ValidateUser(username, email, password); user {
			userSession, sessionId := CreateSessionId(username)
			db.AddToCache(sessionKey, userSession)
			db.SaveCache()

			expires := time.Now().Add(180 * 24 * time.Hour)

			http.SetCookie(w, &http.Cookie{
				Name:     "session-token",
				Value:    sessionId,
				Expires:  expires,
				Path:     "/",
				HttpOnly: true,
				Secure:   true,
				SameSite: http.SameSiteLaxMode,
			})

			w.Header().Add("HX-Redirect", "/")
			return
		}

		w.Write([]byte("Invalid credentials, refresh and retry"))
	}
}

func SignUpHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		ExecuteTemplate(w, path.Join("public", "auth/sign-up.html"), nil)
	} else if r.Method == "POST" {
		username := r.PostFormValue("username")
		email := r.PostFormValue("email")
		password := r.PostFormValue("password")

		if user := db.SearchCache(userKey, "Username", username); user != nil {
			w.Write([]byte("Username already exists"))
			return
		}

		if user := db.SearchCache(userKey, "Email", email); user != nil {
			w.Write([]byte("Email already exists"))
			return
		}

		user := CreateUser(username, email, password)
		db.AddToCache(userKey, user)
		db.SaveCache()

		w.Header().Add("HX-Redirect", "/auth/log-in")
	}
}

func LogOutHandler(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     "session-token",
		Value:    "",
		Expires:  time.Unix(0, 0),
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
	w.Write([]byte("Logged out"))
}

// Support handlers
func FaqHandler(w http.ResponseWriter, r *http.Request) {
	ExecuteTemplate(w, path.Join("public", "support/faq.html"), nil)
}

func AllInquiriesHandler(w http.ResponseWriter, r *http.Request) {
	sessionId, err := GetSessionCookie(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if result := ValidateAdminStatus(sessionId); !result {
		w.Write([]byte("Invalid permissions"))
		return
	}

	inquiries := db.GetCache(inquiryKey)
	ExecuteTemplate(w, path.Join("public", "support/inquiries.html"), inquiries)
}

func ShowInquiryByIdHandler(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	inquiry := db.SearchCache(inquiryKey, "Id", id)

	ExecuteTemplate(w, path.Join("public", "support/inquiry.html"), inquiry)
}

func InquiryHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		_, err := r.Cookie("session-token")

		if err != nil {
			switch {
			case errors.Is(err, http.ErrNoCookie):
                http.Error(w, "No account found, create an account before attempting to create an inquiry", http.StatusBadRequest)
			default:
				log.Println(err)
				http.Error(w, "Server error", http.StatusInternalServerError)
			}
			return
		}

		ExecuteTemplate(w, path.Join("public", "support/upload.html"), nil)
	} else if r.Method == "POST" {
		sessionId, err := GetSessionCookie(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		userSession, err := GetUserSession(sessionId)
		if err != nil {
			w.Write([]byte("Cookie is invalid"))
			return
		}

		user := db.SearchCache(userKey, "Username", userSession["Username"])

		username := user["Username"].(string)
		email := user["Email"].(string)
		title := r.PostFormValue("title")
		description := r.PostFormValue("description")

		inquiry := CreateInquiry(username, email, title, description)
		db.AddToCache(inquiryKey, inquiry)
		db.SaveCache()

		w.Write([]byte("Created inquiry"))
	}
}

// Main handlers
func IndexHandler(w http.ResponseWriter, r *http.Request) {
	ExecuteTemplate(w, path.Join("public", "main/index.html"), nil)
}

func main() {
	db.LoadCache("blogs.json")
	r := mux.NewRouter()

	r.PathPrefix("/public/").Handler(http.StripPrefix("/public/", http.FileServer(http.Dir("./public"))))

	r.HandleFunc("/blog/upload", UploadBlogHandler)
	r.HandleFunc("/blog/all", ShowAllBlogsHandler)
	r.HandleFunc("/blog/{id}", ShowBlogByIdHandler)

	r.HandleFunc("/auth/sign-up", SignUpHandler)
	r.HandleFunc("/auth/log-in", LogInHandler)
	r.HandleFunc("/auth/log-out", LogOutHandler)

	r.HandleFunc("/support/faq", FaqHandler)
	r.HandleFunc("/support/inquiry", InquiryHandler)
	r.HandleFunc("/support/inquiry/all", AllInquiriesHandler)
	r.HandleFunc("/support/inquiry/{id}", ShowInquiryByIdHandler)
	r.HandleFunc("/support/inquiry/{id}/reply", ShowInquiryByIdHandler)

	r.HandleFunc("/", IndexHandler)

	log.Println("Server started on port 3000")
	log.Fatal(http.ListenAndServe(":3000", r))
}
