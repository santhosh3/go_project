/*
{
  "name":"santhosh",
  "repo_url":"http://github.com/pproe/learning",
  "status":"done",
  "dependencies": ["react","react-dom"],
  "site_url":"http://github.com/pproe/learning",
  "description":"checking",
  "dev_dependencies":["react","react-dom"]
}
{
	"username" : "santhosh",
	"password" : "123456"
}
*/

package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
	"github.com/justinas/alice"
	"github.com/lib/pq"
	"github.com/xeipuuv/gojsonschema"
	"golang.org/x/crypto/bcrypt"
)

type RouterResponse struct {
	Message string `json:"message"`
	ID      string `json:"id"`
}

type UserResponse struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Token    string `json:"token"`
}

type Credentials struct {
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
}

type Claims struct {
	Username string `json:"username"`
	ID       string `json:"id"`
	jwt.RegisteredClaims
}

type Project struct {
	ID              string   `json:"id,omitempty"`
	UserID          string   `json:"user_id,omitempty"`
	Name            string   `json:"name,omitempty"`
	RepoURL         string   `json:"repo_url,omitempty"`
	SiteURL         string   `json:"site_url,omitempty"`
	Description     string   `json:"description,omitempty"`
	Dependencies    []string `json:"dependencies,omitempty"`
	DevDependencies []string `json:"dev_dependencies,omitempty"`
	Status          string   `json:"status,omitempty"`
}

type ErrorResponse struct {
	Message string `json:"message"`
}

type App struct {
	DB     *sql.DB
	JWTKey []byte
}

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Err loading .env file")
	}
	var loadErr error
	userSchema, loadErr := loadSchema("schema/user.json")
	if loadErr != nil {
		log.Fatalf("Error loading user schema: %v", loadErr)
	}
	projectSchema, loadErr := loadSchema("schema/project.json")
	if loadErr != nil {
		log.Fatalf("Error loading user schema: %v", loadErr)
	}
	JWTKey := []byte(os.Getenv("JWT_KEY"))
	if len(JWTKey) == 0 {
		log.Fatal("JWT_SECRET key is not set in .env file")
	}
	connStr := os.Getenv("POSTGRES_URL")
	if len(connStr) == 0 {
		log.Fatal("POSTGRES_URL is not set in .env file")
	}

	DB, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal(err)
	}
	defer DB.Close()

	app := &App{DB: DB}

	log.Println("Server Starting....")
	router := mux.NewRouter()
	log.Println("Setting up routes....")
	setUpRoutes(router, app, projectSchema, userSchema)
	log.Println("Server is Listening on port 5000....")
	log.Fatal(http.ListenAndServe(":5000", router))
}

func setUpRoutes(router *mux.Router, app *App, userSchema, projectSchema string) {
	// Middleware and routes for user data
	userChain := alice.New(loggingMiddleware, validateMiddleware(userSchema))
	router.Handle("/register", userChain.ThenFunc(app.register)).Methods("POST")
	router.Handle("/login", userChain.ThenFunc(app.login)).Methods("POST")

	// Middleware and routes for project data
	projectChain := alice.New(loggingMiddleware, app.jwtMiddleware)
	router.Handle("/projects/{id}", projectChain.ThenFunc(app.getProject)).Methods("GET")
	router.Handle("/projects", projectChain.ThenFunc(app.getProjects)).Methods("GET")
	router.Handle("/projects/{id}", projectChain.ThenFunc(app.deleteProject)).Methods("DELETE")

	projectChainWIthValidation := projectChain.Append(validateMiddleware(projectSchema))
	router.Handle("/projects", projectChainWIthValidation.ThenFunc(app.createProject)).Methods("POST")
	router.Handle("/projects/{id}", projectChainWIthValidation.ThenFunc(app.updateProject)).Methods("PUT")
}

// logging Middleware
func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s %s\n,", r.RemoteAddr, r.Method, r.URL)
		next.ServeHTTP(w, r)
	})
}

func loadSchema(filePath string) (string, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// jwt Middleware
func (app *App) jwtMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s %s\n", r.RemoteAddr, r.Method, r.URL)
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			responseWithError(w, http.StatusUnauthorized, "No token provided")
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		if tokenString == authHeader { // Handle missing "Bearer " prefix
			responseWithError(w, http.StatusUnauthorized, "Invalid token format1")
			return
		}

		claims := &Claims{}
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			return app.JWTKey, nil
		})

		if err != nil {
			if err == jwt.ErrSignatureInvalid {
				responseWithError(w, http.StatusUnauthorized, "Invalid token signature 160")
				return
			}
			responseWithError(w, http.StatusBadRequest, "Invalid token")
			return
		}

		if !token.Valid {
			responseWithError(w, http.StatusUnauthorized, "Invalid token")
			return
		}

		ctx := context.WithValue(r.Context(), "claims", claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func validateMiddleware(schema string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var body map[string]interface{}
			bodyBytes, err := io.ReadAll(r.Body)
			if err != nil {
				responseWithError(w, http.StatusBadRequest, "Invalid request payload 183")
				return
			}
			err = json.Unmarshal(bodyBytes, &body)
			if err != nil {
				responseWithError(w, http.StatusBadRequest, "Invalid request payload 188")
				return
			}

			r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes)) // Reassign r.Body before further processing

			schemaLoader := gojsonschema.NewStringLoader(schema)
			documentLoader := gojsonschema.NewGoLoader(body)
			result, err := gojsonschema.Validate(schemaLoader, documentLoader)
			if err != nil {
				responseWithError(w, http.StatusInternalServerError, "Error validating JSON")
				return
			}
			if !result.Valid() {
				var errs []string
				for _, err := range result.Errors() {
					errs = append(errs, err.String())
				}
				responseWithError(w, http.StatusBadRequest, strings.Join(errs, ", "))
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func responseWithError(w http.ResponseWriter, code int, message string) {
	w.Header().Set("Content-type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(ErrorResponse{Message: message})
}

func (app *App) generateToken(username, ID string) (string, error) {
	expirationTime := time.Now().Add(1 * time.Hour)
	Claims := &Claims{
		Username: username,
		ID:       ID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, Claims)
	tokenString, err := token.SignedString(app.JWTKey)
	if err != nil {
		return "", err
	}
	return tokenString, nil
}

// register
func (app *App) register(w http.ResponseWriter, r *http.Request) {
	var creds Credentials
	err := json.NewDecoder(r.Body).Decode(&creds)
	fmt.Println(creds)
	if err != nil {
		responseWithError(w, http.StatusBadRequest, "Invalid request payload 244")
		return
	}
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(creds.Password), bcrypt.DefaultCost)
	if err != nil {
		responseWithError(w, http.StatusInternalServerError, "Error hashing Password")
	}
	var ID string
	err = app.DB.QueryRow("INSERT INTO \"users\" (username,password) VALUES ($1,$2) RETURNING id", creds.Username, string(hashedPassword)).Scan(&ID)
	if err != nil {
		responseWithError(w, http.StatusInternalServerError, "Error creating user")
		return
	}
	tokenString, err := app.generateToken(creds.Username, ID)
	if err != nil {
		responseWithError(w, http.StatusUnauthorized, "Error generating token")
		return
	}

	w.Header().Set("Content-type", "application/json")
	json.NewEncoder(w).Encode(UserResponse{ID: ID, Username: creds.Username, Token: tokenString})
}

// login
func (app *App) login(w http.ResponseWriter, r *http.Request) {
	var creds Credentials
	err := json.NewDecoder(r.Body).Decode(&creds)
	if err != nil {
		responseWithError(w, http.StatusBadRequest, "Invalid request payload 272")
	}

	var storedCreds Credentials
	var ID string
	err = app.DB.QueryRow("SELECT id,username,password FROM \"users\" where username=$1", creds.Username).Scan(&ID, &storedCreds.Username, &storedCreds.Password)
	if err != nil {
		if err == sql.ErrNoRows {
			responseWithError(w, http.StatusUnauthorized, "Invalid username or password")
			return
		}
		responseWithError(w, http.StatusInternalServerError, "Invalid request payload 283")
		return
	}
	err = bcrypt.CompareHashAndPassword([]byte(storedCreds.Password), []byte(creds.Password))
	fmt.Println(err)
	if err != nil {
		responseWithError(w, http.StatusUnauthorized, "Invalid username or password")
		return
	}
	tokenString, err := app.generateToken(creds.Username, ID)
	if err != nil {
		responseWithError(w, http.StatusUnauthorized, "Error generating token")
		return
	}

	w.Header().Set("Content-type", "application/json")
	json.NewEncoder(w).Encode(UserResponse{ID: ID, Username: creds.Username, Token: tokenString})
}

// createProject
func (app *App) createProject(w http.ResponseWriter, r *http.Request) {
	var project Project
	err := json.NewDecoder(r.Body).Decode(&project)
	fmt.Print(err)
	if err != nil {
		responseWithError(w, http.StatusInternalServerError, "Invalid request payload 307")
		return
	}
	claims := r.Context().Value("claims").(*Claims)
	userId := claims.ID
	var ID string
	err = app.DB.QueryRow(
		"INSERT INTO projects (user_id,name,repo_url,site_url,description,dependencies,dev_dependencies,status) VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id",
		userId,
		project.Name,
		project.RepoURL,
		project.SiteURL,
		project.Description,
		pq.Array(project.Dependencies),
		pq.Array(project.DevDependencies),
		project.Status,
	).Scan(&ID)
	if err != nil {
		fmt.Println(err)
		responseWithError(w, http.StatusInternalServerError, "Invalid request payload 318")
		return
	}
	project.ID = ID
	project.UserID = userId
	w.Header().Set("Content-type", "application/json")
	json.NewEncoder(w).Encode(project)
}

// updateProject
func (app *App) updateProject(w http.ResponseWriter, r *http.Request) {
	var project Project
	err := json.NewDecoder(r.Body).Decode(&project)
	fmt.Print(err)
	if err != nil {
		responseWithError(w, http.StatusInternalServerError, "Invalid request payload 307")
		return
	}
	var storedUserID string
	vars := mux.Vars(r)
	id := vars["id"]

	claims := r.Context().Value("claims").(*Claims)
	userId := claims.ID
	err = app.DB.QueryRow("SELECT \"user_id\" FROM projects WHERE id = $1", id).Scan(&storedUserID)
	if err != nil {
		if err == sql.ErrNoRows {
			fmt.Println(err)
			responseWithError(w, http.StatusInternalServerError, "Project not Found 371")
			return
		}
		fmt.Println(err)
		responseWithError(w, http.StatusInternalServerError, "Error fetching project 375")
		return
	}
	if storedUserID != userId {
		fmt.Println(err)
		responseWithError(w, http.StatusForbidden, "You dont have permission to update this project 380")
		return
	}
	_, err = app.DB.Exec(
		"UPDATE projects SET name=$1, repo_url=$2, site_url=$3, description=$4, dependencies=$5, dev_dependencies=$6, status=$7 WHERE id=$8 AND \"user_id\"=$9",
		project.Name,
		project.RepoURL,
		project.SiteURL,
		project.Description,
		pq.Array(project.Dependencies),
		pq.Array(project.DevDependencies),
		project.Status,
		id,
		userId,
	)
	if err != nil {
		fmt.Println(err)
		responseWithError(w, http.StatusInternalServerError, "Error updating Project, 397")
		return
	}
	project.ID = id
	project.UserID = userId
	w.Header().Set("Content-type", "application/json")
	json.NewEncoder(w).Encode(project)
}

// getProjects
func (app *App) getProjects(w http.ResponseWriter, r *http.Request) {
	claims := r.Context().Value("claims").(*Claims)
	userID := claims.ID

	rows, err := app.DB.Query(
		"SELECT id, \"user_id\", name, repo_url, site_url, description,dependencies, dev_dependencies, status FROM projects WHERE \"user_id\"=$1", userID,
	)
	if err != nil {
		fmt.Println(err)
		responseWithError(w, http.StatusInternalServerError, "Error fetching Projects, 370")
		return
	}
	defer rows.Close()
	var projects []Project
	for rows.Next() {
		var project Project
		var dependencies, devDependencies []string

		err := rows.Scan(&project.ID, &project.UserID, &project.Name, &project.RepoURL, &project.SiteURL, &project.Description, pq.Array(&dependencies), pq.Array(&devDependencies), &project.Status)
		if err != nil {
			fmt.Println(err)
			responseWithError(w, http.StatusInternalServerError, "Error Scanning Project 382")
			return
		}
		project.Dependencies = dependencies
		project.DevDependencies = devDependencies
		projects = append(projects, project)
	}
	err = rows.Err()
	if err != nil {
		fmt.Println(err)
		responseWithError(w, http.StatusInternalServerError, "Error fetching project 392")
		return
	}
	w.Header().Set("Content-type", "application/json")
	json.NewEncoder(w).Encode(projects)
}

// getProject
func (app *App) getProject(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]
	claims := r.Context().Value("claims").(*Claims)
	userID := claims.ID
	var project Project
	var dependencies, devDependencies []string
	err := app.DB.QueryRow(
		"SELECT id, \"user_id\", name, repo_url, site_url, description,dependencies, dev_dependencies, status FROM projects WHERE \"user_id\"=$1 AND id = $2", userID, id,
	).Scan(&project.ID, &project.UserID, &project.Name, &project.RepoURL, &project.SiteURL, &project.Description, pq.Array(&dependencies), pq.Array(&devDependencies), &project.Status)

	if err != nil {
		if err == sql.ErrNoRows {
			fmt.Println(err)
			responseWithError(w, http.StatusInternalServerError, "Project not Found 392")
			return
		}
		fmt.Println(err)
		responseWithError(w, http.StatusInternalServerError, "Error fetching project 392")
		return
	}
	project.Dependencies = dependencies
	project.DevDependencies = devDependencies
	w.Header().Set("Content-type", "application/json")
	json.NewEncoder(w).Encode(project)
}

// deleteProject
func (app *App) deleteProject(w http.ResponseWriter, r *http.Request) {
	var storedUserID string
	vars := mux.Vars(r)
	id := vars["id"]

	claims := r.Context().Value("claims").(*Claims)
	userId := claims.ID
	err := app.DB.QueryRow("SELECT \"user_id\" FROM projects WHERE id = $1", id).Scan(&storedUserID)
	if err != nil {
		if err == sql.ErrNoRows {
			fmt.Println(err)
			responseWithError(w, http.StatusInternalServerError, "Project not Found 371")
			return
		}
		fmt.Println(err)
		responseWithError(w, http.StatusInternalServerError, "Error fetching project 375")
		return
	}
	if storedUserID != userId {
		fmt.Println(err)
		responseWithError(w, http.StatusForbidden, "You dont have permission to update this project 380")
		return
	}

	_, err = app.DB.Exec("DELETE FROM projects WHERE id=$1 AND \"user_id\"=$2", id, userId)
	if err != nil {
		fmt.Println(err)
		responseWithError(w, http.StatusInternalServerError, "Error deleting project 501")
		return
	}
	w.Header().Set("Content-type", "application/json")
	json.NewEncoder(w).Encode(RouterResponse{Message: "Project deleted successfully"})
}
