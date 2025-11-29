package main

import (
	"bufio"
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"github.com/skip2/go-qrcode"
	"golang.org/x/crypto/bcrypt"
)

// Configuration
const (
	jwtSecret     = "your-super-secret-jwt-key-change-in-production"
	tokenDuration = 15 * time.Minute
	otpDuration   = 5 * time.Minute
)

// Role constants
const (
	RoleAdmin     = "admin"
	RoleUser      = "user"
	RoleModerator = "moderator"
)

// Permission constants
const (
	PermReadUsers   = "read:users"
	PermWriteUsers  = "write:users"
	PermDeleteUsers = "delete:users"
	PermReadPosts   = "read:posts"
	PermWritePosts  = "write:posts"
	PermDeletePosts = "delete:posts"
)

// User represents a user in the system
type User struct {
	ID           string
	Username     string
	Email        string
	PasswordHash string
	Role         string
	MFAEnabled   bool
	MFASecret    string
	CreatedAt    time.Time
}

// Claims represents JWT claims
type Claims struct {
	UserID   string `json:"user_id"`
	Username string `json:"username"`
	Role     string `json:"role"`
	jwt.RegisteredClaims
}

// OTP represents a one-time password
type OTP struct {
	Code      string
	ExpiresAt time.Time
}

// UserStore manages users in memory
type UserStore struct {
	users map[string]*User
	mu    sync.RWMutex
}

// OTPStore manages OTPs
type OTPStore struct {
	otps map[string]*OTP
	mu   sync.RWMutex
}

// TokenBlacklist manages revoked tokens
type TokenBlacklist struct {
	tokens map[string]time.Time
	mu     sync.RWMutex
}

// AuthSystem is the main authentication system
type AuthSystem struct {
	userStore      *UserStore
	otpStore       *OTPStore
	tokenBlacklist *TokenBlacklist
	rolePermMap    map[string][]string
}

// NewAuthSystem creates a new authentication system
func NewAuthSystem() *AuthSystem {
	as := &AuthSystem{
		userStore:      &UserStore{users: make(map[string]*User)},
		otpStore:       &OTPStore{otps: make(map[string]*OTP)},
		tokenBlacklist: &TokenBlacklist{tokens: make(map[string]time.Time)},
		rolePermMap:    make(map[string][]string),
	}

	// Define role permissions
	as.rolePermMap[RoleAdmin] = []string{
		PermReadUsers, PermWriteUsers, PermDeleteUsers,
		PermReadPosts, PermWritePosts, PermDeletePosts,
	}
	as.rolePermMap[RoleModerator] = []string{
		PermReadUsers, PermReadPosts, PermWritePosts, PermDeletePosts,
	}
	as.rolePermMap[RoleUser] = []string{
		PermReadPosts, PermWritePosts,
	}

	// Create default users
	as.createDefaultUsers()

	return as
}

// createDefaultUsers creates some default users for testing
func (as *AuthSystem) createDefaultUsers() {
	users := []struct {
		username string
		email    string
		password string
		role     string
	}{
		{"admin", "admin@example.com", "admin123", RoleAdmin},
		{"john", "john@example.com", "john123", RoleUser},
		{"moderator", "mod@example.com", "mod123", RoleModerator},
	}

	for _, u := range users {
		as.Register(u.username, u.email, u.password, u.role)
	}
}

// HashPassword hashes a password using bcrypt
func HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(hash), err
}

// CheckPassword checks if password matches hash
func CheckPassword(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// Register registers a new user
func (as *AuthSystem) Register(username, email, password, role string) error {
	as.userStore.mu.Lock()
	defer as.userStore.mu.Unlock()

	// Check if user exists
	for _, user := range as.userStore.users {
		if user.Username == username || user.Email == email {
			return fmt.Errorf("user already exists")
		}
	}

	// Hash password
	hash, err := HashPassword(password)
	if err != nil {
		return err
	}

	// Create user
	user := &User{
		ID:           generateID(),
		Username:     username,
		Email:        email,
		PasswordHash: hash,
		Role:         role,
		MFAEnabled:   false,
		CreatedAt:    time.Now(),
	}

	as.userStore.users[user.ID] = user
	return nil
}

// Login authenticates a user and returns a JWT token
func (as *AuthSystem) Login(username, password string) (string, *User, error) {
	as.userStore.mu.RLock()
	defer as.userStore.mu.RUnlock()

	// Find user
	var user *User
	for _, u := range as.userStore.users {
		if u.Username == username {
			user = u
			break
		}
	}

	if user == nil {
		return "", nil, fmt.Errorf("invalid credentials")
	}

	// Check password
	if !CheckPassword(password, user.PasswordHash) {
		return "", nil, fmt.Errorf("invalid credentials")
	}

	// If MFA is enabled, don't generate token yet
	if user.MFAEnabled {
		return "", user, fmt.Errorf("MFA_REQUIRED")
	}

	// Generate JWT token
	token, err := as.GenerateToken(user)
	if err != nil {
		return "", nil, err
	}

	return token, user, nil
}

// GenerateToken generates a JWT token for a user
func (as *AuthSystem) GenerateToken(user *User) (string, error) {
	claims := Claims{
		UserID:   user.ID,
		Username: user.Username,
		Role:     user.Role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(tokenDuration)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "auth-system",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(jwtSecret))
}

// ValidateToken validates a JWT token
func (as *AuthSystem) ValidateToken(tokenString string) (*Claims, error) {
	// Check if token is blacklisted
	as.tokenBlacklist.mu.RLock()
	if exp, exists := as.tokenBlacklist.tokens[tokenString]; exists {
		as.tokenBlacklist.mu.RUnlock()
		if time.Now().Before(exp) {
			return nil, fmt.Errorf("token has been revoked")
		}
	}
	as.tokenBlacklist.mu.RUnlock()

	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return []byte(jwtSecret), nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		return claims, nil
	}

	return nil, fmt.Errorf("invalid token")
}

// RevokeToken adds a token to the blacklist
func (as *AuthSystem) RevokeToken(tokenString string, expiresAt time.Time) {
	as.tokenBlacklist.mu.Lock()
	defer as.tokenBlacklist.mu.Unlock()
	as.tokenBlacklist.tokens[tokenString] = expiresAt
}

// HasPermission checks if a role has a specific permission
func (as *AuthSystem) HasPermission(role, permission string) bool {
	perms, exists := as.rolePermMap[role]
	if !exists {
		return false
	}

	for _, p := range perms {
		if p == permission {
			return true
		}
	}
	return false
}

// EnableMFA enables MFA for a user and generates TOTP QR code
func (as *AuthSystem) EnableMFA(userID string) (string, error) {
	as.userStore.mu.Lock()
	defer as.userStore.mu.Unlock()

	user, exists := as.userStore.users[userID]
	if !exists {
		return "", fmt.Errorf("user not found")
	}

	// Generate TOTP key
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "JWTAuthSystem",
		AccountName: user.Email,
	})
	if err != nil {
		return "", err
	}

	// Store the secret
	user.MFASecret = key.Secret()
	user.MFAEnabled = true

	// Generate QR code
	qrFile := fmt.Sprintf("qr_%s.png", user.Username)
	err = qrcode.WriteFile(key.String(), qrcode.Medium, 256, qrFile)
	if err != nil {
		return "", err
	}

	return key.Secret(), nil
}

// GenerateOTP generates a 6-digit OTP
func (as *AuthSystem) GenerateOTP(userID string) (string, error) {
	code := generateOTPCode()

	as.otpStore.mu.Lock()
	defer as.otpStore.mu.Unlock()

	as.otpStore.otps[userID] = &OTP{
		Code:      code,
		ExpiresAt: time.Now().Add(otpDuration),
	}

	return code, nil
}

// VerifyOTP verifies an email OTP code
func (as *AuthSystem) VerifyOTP(userID, code string) bool {
	as.otpStore.mu.Lock()
	defer as.otpStore.mu.Unlock()

	otp, exists := as.otpStore.otps[userID]
	if !exists {
		return false
	}

	if time.Now().After(otp.ExpiresAt) {
		delete(as.otpStore.otps, userID)
		return false
	}

	if otp.Code == code {
		delete(as.otpStore.otps, userID)
		return true
	}

	return false
}

// VerifyTOTP verifies a TOTP code from authenticator app
func (as *AuthSystem) VerifyTOTP(userID, code string) bool {
	as.userStore.mu.RLock()
	user, exists := as.userStore.users[userID]
	as.userStore.mu.RUnlock()

	if !exists || !user.MFAEnabled {
		return false
	}

	// Verify TOTP code with time skew tolerance
	// Allow 1 period before and after (90 seconds total window)
	valid, err := totp.ValidateCustom(
		code,
		user.MFASecret,
		time.Now(),
		totp.ValidateOpts{
			Period:    30,
			Skew:      1,  // Allow 1 time step before/after
			Digits:    6,
			Algorithm: otp.AlgorithmSHA1,
		},
	)
	
	if err != nil {
		fmt.Printf("🐛 TOTP validation error: %v\n", err)
		return false
	}
	
	return valid
}

// GetUserByID retrieves a user by ID
func (as *AuthSystem) GetUserByID(userID string) (*User, error) {
	as.userStore.mu.RLock()
	defer as.userStore.mu.RUnlock()

	user, exists := as.userStore.users[userID]
	if !exists {
		return nil, fmt.Errorf("user not found")
	}

	return user, nil
}

// ListUsers lists all users (admin only)
func (as *AuthSystem) ListUsers() []*User {
	as.userStore.mu.RLock()
	defer as.userStore.mu.RUnlock()

	users := make([]*User, 0, len(as.userStore.users))
	for _, user := range as.userStore.users {
		users = append(users, user)
	}
	return users
}

// Helper functions
func generateID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}

func generateMFASecret() string {
	b := make([]byte, 20)
	rand.Read(b)
	return base32.StdEncoding.EncodeToString(b)
}

func generateOTPCode() string {
	max := big.NewInt(1000000)
	n, _ := rand.Int(rand.Reader, max)
	return fmt.Sprintf("%06d", n.Int64())
}

// Menu-driven CLI
func displayMainMenu() {
	fmt.Println("\n╔════════════════════════════════════════════╗")
	fmt.Println("║     JWT AUTHENTICATION SYSTEM              ║")
	fmt.Println("╚════════════════════════════════════════════╝")
	fmt.Println("1. Register New User")
	fmt.Println("2. Login")
	fmt.Println("3. Test Token Validation")
	fmt.Println("4. Check Permissions (RBAC)")
	fmt.Println("5. Enable MFA")
	fmt.Println("6. List All Users (Admin)")
	fmt.Println("7. Start REST API Server")
	fmt.Println("8. View Role Permissions")
	fmt.Println("9. Logout (Revoke Token)")
	fmt.Println("10. Exit")
	fmt.Print("\nEnter your choice: ")
}

func readInput(reader *bufio.Reader) string {
	input, _ := reader.ReadString('\n')
	return strings.TrimSpace(input)
}

func registerUser(as *AuthSystem, reader *bufio.Reader) {
	fmt.Println("\n--- User Registration ---")
	fmt.Print("Username: ")
	username := readInput(reader)
	fmt.Print("Email: ")
	email := readInput(reader)
	fmt.Print("Password: ")
	password := readInput(reader)
	fmt.Print("Role (admin/moderator/user): ")
	role := readInput(reader)

	if role != RoleAdmin && role != RoleModerator && role != RoleUser {
		role = RoleUser
	}

	err := as.Register(username, email, password, role)
	if err != nil {
		fmt.Printf("❌ Registration failed: %v\n", err)
	} else {
		fmt.Println("✅ User registered successfully!")
		fmt.Printf("📋 Username: %s\n", username)
		fmt.Printf("📋 Role: %s\n", role)
	}
}

func loginUser(as *AuthSystem, reader *bufio.Reader) string {
	fmt.Println("\n--- User Login ---")
	fmt.Print("Username: ")
	username := readInput(reader)
	fmt.Print("Password: ")
	password := readInput(reader)

	token, user, err := as.Login(username, password)
	if err != nil {
		if err.Error() == "MFA_REQUIRED" {
			fmt.Println("\n🔐 MFA is enabled for this account")
			fmt.Println("\nChoose MFA method:")
			fmt.Println("1. Email OTP (simulated)")
			fmt.Println("2. Authenticator App (TOTP)")
			fmt.Print("Choice: ")
			choice := readInput(reader)

			if choice == "1" {
				// Email OTP method
				otp, _ := as.GenerateOTP(user.ID)
				fmt.Printf("\n📧 OTP sent to email (simulated): %s\n", otp)
				fmt.Print("Enter OTP: ")
				otpInput := readInput(reader)

				if as.VerifyOTP(user.ID, otpInput) {
					token, err = as.GenerateToken(user)
					if err == nil {
						fmt.Println("✅ Login successful with Email OTP!")
						fmt.Printf("🎫 Token: %s\n", token)
						fmt.Printf("👤 User: %s (%s)\n", user.Username, user.Role)
						return token
					}
				} else {
					fmt.Println("❌ Invalid OTP")
					return ""
				}
			} else if choice == "2" {
				// TOTP Authenticator App method
				fmt.Println("\n📱 Open your Authenticator App (Google Authenticator, Authy, etc.)")
				fmt.Println("💡 The code refreshes every 30 seconds")
				fmt.Print("\nEnter 6-digit code from app: ")
				totpCode := readInput(reader)

				// Show what we're verifying
				fmt.Printf("🔍 Verifying code: %s\n", totpCode)
				
				if as.VerifyTOTP(user.ID, totpCode) {
					token, err = as.GenerateToken(user)
					if err == nil {
						fmt.Println("✅ Login successful with Authenticator!")
						fmt.Printf("🎫 Token: %s\n", token)
						fmt.Printf("👤 User: %s (%s)\n", user.Username, user.Role)
						return token
					}
				} else {
					fmt.Println("❌ Invalid code from Authenticator")
					fmt.Println("💡 Tips:")
					fmt.Println("   • Make sure time is synced on your phone")
					fmt.Println("   • Try the newest code from the app")
					fmt.Println("   • Wait for the code to refresh and try again")
					return ""
				}
			} else {
				fmt.Println("❌ Invalid choice")
				return ""
			}
		}
		fmt.Printf("❌ Login failed: %v\n", err)
		return ""
	}

	fmt.Println("✅ Login successful!")
	fmt.Printf("🎫 Token: %s\n", token)
	fmt.Printf("👤 User: %s (%s)\n", user.Username, user.Role)
	fmt.Printf("⏰ Expires: %v\n", time.Now().Add(tokenDuration).Format(time.RFC3339))
	return token
}

func validateToken(as *AuthSystem, reader *bufio.Reader) {
	fmt.Println("\n--- Validate Token ---")
	fmt.Print("Enter JWT token: ")
	token := readInput(reader)

	claims, err := as.ValidateToken(token)
	if err != nil {
		fmt.Printf("❌ Invalid token: %v\n", err)
		return
	}

	fmt.Println("✅ Token is valid!")
	fmt.Printf("👤 User ID: %s\n", claims.UserID)
	fmt.Printf("👤 Username: %s\n", claims.Username)
	fmt.Printf("🎭 Role: %s\n", claims.Role)
	fmt.Printf("⏰ Issued: %v\n", claims.IssuedAt.Time.Format(time.RFC3339))
	fmt.Printf("⏰ Expires: %v\n", claims.ExpiresAt.Time.Format(time.RFC3339))
}

func checkPermissions(as *AuthSystem, reader *bufio.Reader) {
	fmt.Println("\n--- Check Permissions (RBAC) ---")
	fmt.Println("Available permissions:")
	fmt.Println("  - read:users, write:users, delete:users")
	fmt.Println("  - read:posts, write:posts, delete:posts")
	fmt.Print("\nRole (admin/moderator/user): ")
	role := readInput(reader)
	fmt.Print("Permission: ")
	permission := readInput(reader)

	hasPermission := as.HasPermission(role, permission)
	if hasPermission {
		fmt.Printf("✅ Role '%s' HAS permission '%s'\n", role, permission)
	} else {
		fmt.Printf("❌ Role '%s' DOES NOT have permission '%s'\n", role, permission)
	}
}

func enableMFA(as *AuthSystem, reader *bufio.Reader) {
	fmt.Println("\n--- Enable MFA ---")
	fmt.Print("Enter username: ")
	username := readInput(reader)

	// Find user
	var userID string
	var userEmail string
	for _, user := range as.ListUsers() {
		if user.Username == username {
			userID = user.ID
			userEmail = user.Email
			break
		}
	}

	if userID == "" {
		fmt.Println("❌ User not found")
		return
	}

	secret, err := as.EnableMFA(userID)
	if err != nil {
		fmt.Printf("❌ Failed to enable MFA: %v\n", err)
		return
	}

	qrFile := fmt.Sprintf("qr_%s.png", username)
	
	fmt.Println("\n✅ MFA enabled successfully!")
	fmt.Println("\n📱 Setup Instructions:")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println("1. Install an Authenticator App:")
	fmt.Println("   • Google Authenticator (Android/iOS)")
	fmt.Println("   • Microsoft Authenticator")
	fmt.Println("   • Authy")
	fmt.Println("   • Any TOTP-compatible app")
	fmt.Println()
	fmt.Printf("2. Open the QR code image: %s\n", qrFile)
	fmt.Println("   (Located in the same folder as this program)")
	fmt.Println()
	fmt.Println("3. In your Authenticator App:")
	fmt.Println("   • Tap 'Add' or '+' button")
	fmt.Println("   • Select 'Scan QR Code'")
	fmt.Println("   • Scan the QR code from the image")
	fmt.Println()
	fmt.Println("4. The app will show a 6-digit code that changes every 30 seconds")
	fmt.Println()
	fmt.Println("5. Use this code when logging in!")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Printf("\n🔑 Manual Entry Secret (if QR doesn't work): %s\n", secret)
	fmt.Printf("📧 Account: %s\n", userEmail)
	fmt.Println("🏢 Issuer: JWTAuthSystem")
	fmt.Println("\n💡 You can also use Email OTP option during login")
	
	// Test current TOTP code
	fmt.Println("\n🧪 Testing TOTP generation...")
	testCode, err := totp.GenerateCode(secret, time.Now())
	if err == nil {
		fmt.Printf("✅ Current valid code (for testing): %s\n", testCode)
		fmt.Println("   (This code changes every 30 seconds)")
	}
}

func listUsers(as *AuthSystem) {
	fmt.Println("\n--- All Users ---")
	users := as.ListUsers()

	if len(users) == 0 {
		fmt.Println("No users found")
		return
	}

	for i, user := range users {
		fmt.Printf("\n[%d] User Details:\n", i+1)
		fmt.Printf("  ID: %s\n", user.ID)
		fmt.Printf("  Username: %s\n", user.Username)
		fmt.Printf("  Email: %s\n", user.Email)
		fmt.Printf("  Role: %s\n", user.Role)
		fmt.Printf("  MFA Enabled: %v\n", user.MFAEnabled)
		fmt.Printf("  Created: %v\n", user.CreatedAt.Format(time.RFC3339))
	}
}

func viewRolePermissions(as *AuthSystem) {
	fmt.Println("\n--- Role Permissions Matrix ---")
	for role, perms := range as.rolePermMap {
		fmt.Printf("\n🎭 %s:\n", strings.ToUpper(role))
		for _, perm := range perms {
			fmt.Printf("  ✓ %s\n", perm)
		}
	}
}

func revokeToken(as *AuthSystem, reader *bufio.Reader, currentToken *string) {
	fmt.Println("\n--- Logout (Revoke Token) ---")
	if *currentToken == "" {
		fmt.Println("❌ No active token to revoke")
		return
	}

	claims, err := as.ValidateToken(*currentToken)
	if err != nil {
		fmt.Println("❌ Invalid token")
		return
	}

	as.RevokeToken(*currentToken, claims.ExpiresAt.Time)
	fmt.Println("✅ Token revoked successfully (logged out)")
	*currentToken = ""
}

// REST API Server
func startAPIServer(as *AuthSystem) {
	// Login endpoint
	http.HandleFunc("/api/login", func(w http.ResponseWriter, r *http.Request) {
		fmt.Printf("\n[%s] Incoming request: %s %s\n", time.Now().Format("15:04:05"), r.Method, r.URL.Path)
		
		if r.Method != http.MethodPost {
			fmt.Println("❌ Error: Method not allowed")
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		username := r.FormValue("username")
		password := r.FormValue("password")
		fmt.Printf("🔑 Login attempt: username=%s\n", username)

		token, user, err := as.Login(username, password)
		if err != nil {
			fmt.Printf("❌ Login failed: %v\n", err)
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		fmt.Printf("✅ Login successful: %s (%s)\n", user.Username, user.Role)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"token":"%s","user":"%s","role":"%s"}`, token, user.Username, user.Role)
	})

	// Protected endpoint (requires valid token)
	http.HandleFunc("/api/protected", func(w http.ResponseWriter, r *http.Request) {
		fmt.Printf("\n[%s] Incoming request: %s %s\n", time.Now().Format("15:04:05"), r.Method, r.URL.Path)
		
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			fmt.Println("❌ Error: Missing token")
			http.Error(w, "Missing token", http.StatusUnauthorized)
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		claims, err := as.ValidateToken(tokenString)
		if err != nil {
			fmt.Printf("❌ Error: Invalid token - %v\n", err)
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		fmt.Printf("✅ Access granted to user: %s (%s)\n", claims.Username, claims.Role)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"message":"Access granted","user":"%s","role":"%s"}`, claims.Username, claims.Role)
	})

	// Admin-only endpoint
	http.HandleFunc("/api/admin/users", func(w http.ResponseWriter, r *http.Request) {
		fmt.Printf("\n[%s] Incoming request: %s %s\n", time.Now().Format("15:04:05"), r.Method, r.URL.Path)
		
		authHeader := r.Header.Get("Authorization")
		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		claims, err := as.ValidateToken(tokenString)
		if err != nil {
			fmt.Printf("❌ Error: Unauthorized - %v\n", err)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		if !as.HasPermission(claims.Role, PermReadUsers) {
			fmt.Printf("❌ Forbidden: User '%s' (role: %s) lacks permission\n", claims.Username, claims.Role)
			http.Error(w, "Forbidden: insufficient permissions", http.StatusForbidden)
			return
		}

		users := as.ListUsers()
		fmt.Printf("✅ Admin access granted to: %s (%s) - Returned %d users\n", claims.Username, claims.Role, len(users))
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"count":%d,"message":"Access granted to admin endpoint"}`, len(users))
	})

	fmt.Println("\n🚀 REST API Server started on http://localhost:8080")
	fmt.Println("\nEndpoints:")
	fmt.Println("  POST   /api/login         - Login (username & password)")
	fmt.Println("  GET    /api/protected     - Protected endpoint (requires token)")
	fmt.Println("  GET    /api/admin/users   - Admin-only endpoint")
	fmt.Println("\nExample:")
	fmt.Println("  curl -X POST http://localhost:8080/api/login -d 'username=admin&password=admin123'")
	fmt.Println()

	if err := http.ListenAndServe(":8080", nil); err != nil {
		fmt.Printf("Server error: %v\n", err)
	}
}

func main() {
	as := NewAuthSystem()
	reader := bufio.NewReader(os.Stdin)
	var currentToken string

	fmt.Println("🔐 Welcome to JWT Authentication System")
	fmt.Println("\n📋 Default Users:")
	fmt.Println("  • admin / admin123 (Admin)")
	fmt.Println("  • john / john123 (User)")
	fmt.Println("  • moderator / mod123 (Moderator)")

	for {
		displayMainMenu()
		choice := readInput(reader)

		switch choice {
		case "1":
			registerUser(as, reader)
		case "2":
			token := loginUser(as, reader)
			if token != "" {
				currentToken = token
			}
		case "3":
			validateToken(as, reader)
		case "4":
			checkPermissions(as, reader)
		case "5":
			enableMFA(as, reader)
		case "6":
			listUsers(as)
		case "7":
			startAPIServer(as)
		case "8":
			viewRolePermissions(as)
		case "9":
			revokeToken(as, reader, &currentToken)
		case "10":
			fmt.Println("\n👋 Goodbye!")
			return
		default:
			fmt.Println("\n❌ Invalid choice! Please try again.")
		}

		if choice != "7" {
			fmt.Print("\nPress Enter to continue...")
			reader.ReadString('\n')
		}
	}
}