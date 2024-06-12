package main 

import "github.com/google/uuid"

// User related functions
func CreateUser(username, email, password string) map[string]interface{} {
	return map[string]interface{}{
		"Id":       uuid.New().String(),
		"Username": username,
		"Email":    email,
		"Password": password,
		"Admin":    false,
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

// Blog related functions
func CreateBlog(title, description string) map[string]interface{} {
	return map[string]interface{}{
		"Id":          uuid.New().String(),
		"Title":       title,
		"Description": description,
	}
}

// Inquiry related functions
func CreateInquiry(username, email, title, description string) map[string]interface{} {
	return map[string]interface{}{
		"Id":          uuid.New().String(),
		"Username":    username,
		"Email":       email,
		"Title":       title,
		"Description": description,
	}
}

func CreateInquiryReply(inquiryId, username, email, title, description string) map[string]interface{} {
	return map[string]interface{}{
		"Id":          inquiryId,
		"Username":    username,
		"Email":       email,
		"Title":       title,
		"Description": description,
	}
}
