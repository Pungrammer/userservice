package userservice

import (
	"encoding/json"
	"log"
	"net/http"
	"time"
	"userservice/requests"

	"github.com/xyproto/permissionbolt"
	"github.com/xyproto/pinterface"
)

type permissionHandler struct {
	// perm is a Permissions structure that can be used to deny requests
	// and acquire the UserState. By using `pinterface.IPermissions` instead
	// of `*permissionbolt.Permissions`, the code is compatible with not only
	// `permissionbolt`, but also other modules that uses other database
	// backends, like `permissions2` which uses Redis.
	perm pinterface.IPermissions

	// The HTTP multiplexer
	mux *http.ServeMux
}

// Implement the ServeHTTP method to make a permissionHandler a http.Handler
func (ph *permissionHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	// Check if the user has the right admin/user rights
	if ph.perm.Rejected(w, req) {
		// Let the user know, by calling the custom "permission denied" function
		ph.perm.DenyFunction()(w, req)
		// Reject the request by not calling the next handler below
		return
	}
	// Serve the requested page if permissions were granted
	ph.mux.ServeHTTP(w, req)
}

func main() {
	defer log.Printf("Shutting down")

	mux := http.NewServeMux()

	// New permissionbolt middleware
	perm, err := permissionbolt.New()
	if err != nil {
		log.Fatal("Cannot init middleware", err)
		return
	}

	// Blank slate, no default permissions
	//perm.Clear()

	// Get the middleware, used in the handlers below
	middleware := perm.UserState()
	err = middleware.SetPasswordAlgo("bcrypt")
	if err != nil {
		log.Fatal("Cannot set password algorithm")
		return
	}

	//TODO: remove this endpoint
	mux.HandleFunc("/info", func(w http.ResponseWriter, req *http.Request) {
		username, _ := middleware.UsernameCookie(req) //ignore error, as it only tells us that there was no cookie
		if username != "" {
			log.Printf("User '%s' is logged in", username)
			log.Printf("User '%s' has user rights?: %v", username, middleware.UserRights(req))
			log.Printf("User '%s' has admin rights?: %v", username, middleware.AdminRights(req))
		} else {
			log.Printf("User is not logged in")
		}
	})

	mux.HandleFunc("/register", func(w http.ResponseWriter, req *http.Request) {
		registerRequest := requests.Register{}
		err := json.NewDecoder(req.Body).Decode(&registerRequest)
		if err != nil {
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}
		middleware.AddUser(registerRequest.Username, registerRequest.Password, "")
		// There won't be a confirmation process
		middleware.MarkConfirmed(registerRequest.Username)
		log.Printf("User %s was created", registerRequest.Username)
	})

	mux.HandleFunc("/admin/remove", func(w http.ResponseWriter, req *http.Request) {
		//middleware.RemoveUser("bob")
		//log.Printf("User bob was removed: %v\n", !middleware.HasUser("bob"))
		http.Error(w, "Not implemented", http.StatusNotImplemented)
	})

	mux.HandleFunc("/login", func(w http.ResponseWriter, req *http.Request) {
		switch req.Method {
		case "POST":
			loginRequest := requests.Login{}
			err := json.NewDecoder(req.Body).Decode(&loginRequest)
			if err != nil {
				http.Error(w, "Malformed input", http.StatusBadRequest)
				return
			}

			if middleware.CorrectPassword(loginRequest.Username, loginRequest.Password) {
				err := middleware.Login(w, loginRequest.Username)
				if err != nil {
					log.Println("Cannot requests user: ", err)
					http.Error(w, "Internal Server error", http.StatusInternalServerError)
					return
				}
				log.Printf("Logged in user %s", loginRequest.Username)
			} else {
				http.Error(w, "Wrong password", http.StatusForbidden)
				return
			}
		default:
			http.Error(w, "Not Found", http.StatusNotFound)
			return
		}
	})

	mux.HandleFunc("/logout", func(w http.ResponseWriter, req *http.Request) {
		username, err := middleware.UsernameCookie(req)
		if err != nil {
			http.Error(w, "Bad request", http.StatusBadRequest)
		}

		middleware.Logout(username)
		log.Printf("%s is now logged out: %v\n", username, !middleware.IsLoggedIn(username))
	})

	mux.HandleFunc("/admin/makeadmin", func(w http.ResponseWriter, req *http.Request) {
		//middleware.SetAdminStatus("bob")
		//log.Printf("bob is now administrator: %v\n", middleware.IsAdmin("bob"))
		http.Error(w, "Not implemented", http.StatusNotImplemented)
	})

	mux.HandleFunc("/data", func(w http.ResponseWriter, req *http.Request) {
		//log.Printf("user page that only logged in users must see!")
		http.Error(w, "Not implemented", http.StatusNotImplemented)
	})

	mux.HandleFunc("/admin", func(w http.ResponseWriter, req *http.Request) {
		//log.Printf("super secret information that only logged in administrators must see!\n\n")
		//if usernames, err := middleware.AllUsernames(); err == nil {
		//	log.Printf("list of all users: " + strings.Join(usernames, ", "))
		//}
		http.Error(w, "Not implemented", http.StatusNotImplemented)
	})

	// Custom handler for when permissions are denied
	perm.SetDenyFunction(func(w http.ResponseWriter, req *http.Request) {
		http.Error(w, "Permission denied!", http.StatusForbidden)
	})

	// Configure the HTTP server and permissionHandler struct
	s := &http.Server{
		Addr:           ":3000", //TODO: Make configurable
		Handler:        &permissionHandler{perm, mux},
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}

	log.Println("Listening for requests on port 3000")

	// Start listening
	err = s.ListenAndServe()
	if err != nil {
		log.Fatal("Failed to start server: ", err)
	}
}
