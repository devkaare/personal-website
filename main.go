package main

import (
	"errors"
	"github.com/devkaare/db2"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"html/template"
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

func CreateInquiry(username, email, title, description string) map[string]interface{} {
	return map[string]interface{}{"Id": uuid.New().String(),
		"Username":    username,
		"Email":       email,
		"Title":       title,
		"Description": description,
	}
}

func CreateSessionId(username string) (map[string]interface{}, string) {
	id := uuid.New().String()

	user := map[string]interface{}{
		"Id":       id,
		"Username": username,
	}

	return user, id
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

func UploadBlogHandler(w http.ResponseWriter, r *http.Request) {
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
		// Validate user before initiating upload
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

		if result := ValidateAdminStatus(cookie.Value); !result {
			w.Write([]byte("Invalid permissions"))
			return
		}

		title := r.PostFormValue("title")
		description := r.PostFormValue("description")

		// Save blog to database (cache)
		blog := CreateBlog(title, description)
		db.AddToCache(blogKey, blog)
		db.SaveCache()

		w.Header().Add("HX-Redirect", "/blog/all")
	}
}

func ShowBlogByIdHandler(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	blog := db.SearchCache(blogKey, "Id", id)

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

func ShowAllBlogsHandler(w http.ResponseWriter, r *http.Request) {
	// Get all blogs from cache
	blogs := db.GetCache(blogKey)

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

func LogInHandler(w http.ResponseWriter, r *http.Request) {
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

		w.Write([]byte("<h1>Authentication Failed</h1><button onclick='window.location.reload();'>Retry</button>"))
	}
}

func SignUpHandler(w http.ResponseWriter, r *http.Request) {
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

func InquiryHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		_, err := r.Cookie("session-token")
		if err != nil {
			switch {
			case errors.Is(err, http.ErrNoCookie):
				fp := path.Join("public", "support/error.html")
				tmpl, err := template.ParseFiles(fp)
				if err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}

				if err := tmpl.Execute(w, map[string]string{"error": "Please create an account before attempting to create inquires"}); err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
				}
			default:
				log.Println(err)
				http.Error(w, "Server error", http.StatusInternalServerError)
			}
			return
		}
		fp := path.Join("public", "support/upload.html")
		tmpl, err := template.ParseFiles(fp)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		if err := tmpl.Execute(w, nil); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	} else if r.Method == "POST" {
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

func ShowInquiryByIdHandler(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	inquiry := db.SearchCache(inquiryKey, "Id", id)
	//log.Println(inquiry)

	fp := path.Join("public", "support/inquiry.html")
	tmpl, err := template.ParseFiles(fp)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if err := tmpl.Execute(w, inquiry); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func AllInquiriesHandler(w http.ResponseWriter, r *http.Request) {
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

	inquiries := db.GetCache(inquiryKey)

	fp := path.Join("public", "support/inquiries.html")
	tmpl, err := template.ParseFiles(fp)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if err := tmpl.Execute(w, inquiries); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func FaqHandler(w http.ResponseWriter, r *http.Request) {
	fp := path.Join("public", "support/faq.html")
	tmpl, err := template.ParseFiles(fp)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if err := tmpl.Execute(w, nil); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func BioHandler(w http.ResponseWriter, r *http.Request) {
	fp := path.Join("public", "main/bio.html")
	tmpl, err := template.ParseFiles(fp)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if err := tmpl.Execute(w, nil); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func GetCookieHandler(w http.ResponseWriter, r *http.Request) {
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

	if result := ValidateSessionId(cookie.Value); !result {
		w.Write([]byte("Cookie is invalid"))
		return
	}

	w.Write([]byte("Cookie is valid"))
}

func AdminCheckHandler(w http.ResponseWriter, r *http.Request) {
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

func main() {
	db.LoadCache("blogs.json")
	r := mux.NewRouter()

	// Serve static files from the public directory
	r.PathPrefix("/public/").Handler(http.StripPrefix("/public/", http.FileServer(http.Dir("./public"))))

	// Blog handlers
	r.HandleFunc("/blog/upload", UploadBlogHandler)
	r.HandleFunc("/blog/all", ShowAllBlogsHandler)
	r.HandleFunc("/blog/{id}", ShowBlogByIdHandler)

	// Account authentication handlers
	r.HandleFunc("/auth/sign-up", SignUpHandler)
	r.HandleFunc("/auth/log-in", LogInHandler)
	r.HandleFunc("/auth/log-out", LogOutHandler)
	r.HandleFunc("/auth/test", GetCookieHandler)
	r.HandleFunc("/auth/admin-dash", AdminCheckHandler)

	// Support handlers
	r.HandleFunc("/support/faq", FaqHandler)
	r.HandleFunc("/support/inquiry", InquiryHandler)
	r.HandleFunc("/support/inquiry/all", AllInquiriesHandler)
	r.HandleFunc("/support/inquiry/{id}", ShowInquiryByIdHandler)

	// Main handlers
	r.HandleFunc("/", BioHandler)

	log.Println("Server started on port 3000")
	log.Fatal(http.ListenAndServe(":3000", r))
}
