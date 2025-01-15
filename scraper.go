package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	_ "github.com/mattn/go-sqlite3"
	"github.com/joho/godotenv"
)

const (
	DB_NAME          = "discord_data.db"
	DISCORD_API_BASE = "https://discord.com/api/v9"
)

var (
	db        *sql.DB
	dbMutex   sync.Mutex
	proxyPool = []string{
		"http://proxy1.example.com",
		"http://proxy2.example.com",
		// Add more proxies here
	}
	proxyIndex = 0
	proxyMutex sync.Mutex
)

func initializeDB() {
	var err error
	db, err = sql.Open("sqlite3", DB_NAME)
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
	}
	createUsersTable()
	createLinkedAccountsTable()
}

func createUsersTable() {
	query := `
	CREATE TABLE IF NOT EXISTS users (
		userid TEXT PRIMARY KEY,
		bio TEXT,
		avatar TEXT,
		banner TEXT,
		accent_color INTEGER
	)
	`
	_, err := db.Exec(query)
	if err != nil {
		log.Fatalf("Failed to create users table: %v", err)
	}
}

func createLinkedAccountsTable() {
	query := `
	CREATE TABLE IF NOT EXISTS linked_accounts (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		userid TEXT,
		account_type TEXT,
		username TEXT,
		website TEXT,
		FOREIGN KEY(userid) REFERENCES users(userid)
	)
	`
	_, err := db.Exec(query)
	if err != nil {
		log.Fatalf("Failed to create linked_accounts table: %v", err)
	}
}

func getHeaders(token string) http.Header {
	return http.Header{
		"Authorization": []string{token},
		"X-Super-Properties": []string{"eyJvcyI6IldpbmRvd3MiLCJicm93c2VyIjoiRmlyZWZveCIsImRldmljZSI6IiIsInN5c3RlbV9sb2NhbGUiOiJlbi1VUyIsImJyb3dzZXJfdXNlcl9hZ2VudCI6Ik1vemlsbGEvNS4wIChXaW5kb3dzIE5UIDEwLjA7IFdpbjY0OyB4NjQ7IHJ2OjkzLjApIEdlY2tvLzIwMTAwMTAxIEZpcmVmb3gvOTMuMCIsImJyb3dzZXJfdmVyc2lvbiI6IjkzLjAiLCJvc192ZXJzaW9uIjoiMTAiLCJyZWZlcnJlciI6IiIsInJlZmVycmluZ19kb21haW4iOiIiLCJyZWZlcnJlcl9jdXJyZW50IjoiIiwicmVsZWFzZV9jaGFubmVsIjoic3RhYmxlIiwiY2xpZW50X2J1aWxkX251bWJlciI6MTAwODA0LCJjbGllbnRfZXZlbnRfc291cmNlIjpudWxsfQ=="},
		"Accept":          []string{"*/*"},
		"Accept-Language": []string{"en-GB"},
		"Content-Type":    []string{"application/json"},
		"User-Agent":      []string{"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) discord/0.0.16 Chrome/91.0.4472.164 Electron/13.4.0 Safari/537.36"},
	}
}

func getProxy() string {
	proxyMutex.Lock()
	defer proxyMutex.Unlock()
	proxy := proxyPool[proxyIndex]
	proxyIndex = (proxyIndex + 1) % len(proxyPool)
	return proxy
}

func checkToken(token string) (int, error) {
	url := fmt.Sprintf("%s/users/@me/affinities/guilds", DISCORD_API_BASE)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return 0, err
	}
	req.Header = getHeaders(token)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	return resp.StatusCode, nil
}

func getUserProfile(token, userID string) (map[string]interface{}, error) {
	url := fmt.Sprintf("%s/users/%s/profile", DISCORD_API_BASE, userID)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header = getHeaders(token)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get user profile: %v", resp.Status)
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return result, nil
}

func getUserMessages(token, channelID string, limit int) ([]map[string]interface{}, error) {
	url := fmt.Sprintf("%s/channels/%s/messages?limit=%d", DISCORD_API_BASE, channelID, limit)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header = getHeaders(token)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get user messages: %v", resp.Status)
	}

	var result []map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return result, nil
}

type IdentifyPayload struct {
	Op int `json:"op"`
	D struct {
		Token         string `json:"token"`
		Capabilities  int    `json:"capabilities"`
		Properties    struct {
			Os                    string `json:"os"`
			Browser              string `json:"browser"`
			Device               string `json:"device"`
			SystemLocale         string `json:"system_locale"`
			BrowserUserAgent     string `json:"browser_user_agent"`
			BrowserVersion       string `json:"browser_version"`
			OsVersion            string `json:"os_version"`
			Referrer             string `json:"referrer"`
			ReferringDomain      string `json:"referring_domain"`
			ReferrerCurrent      string `json:"referrer_current"`
			ReferringDomainCurrent string `json:"referring_domain_current"`
			ReleaseChannel       string `json:"release_channel"`
			ClientBuildNumber    int    `json:"client_build_number"`
			ClientEventSource    *int   `json:"client_event_source"`
		} `json:"properties"`
		Presence struct {
			Status string        `json:"status"`
			Since  int           `json:"since"`
			Activities []interface{} `json:"activities"`
			Afk     bool         `json:"afk"`
		} `json:"presence"`
		Compress     bool `json:"compress"`
		ClientState  struct {
			GuildVersions                map[string]interface{} `json:"guild_versions"`
			HighestLastMessageID        string                 `json:"highest_last_message_id"`
			ReadStateVersion            int                    `json:"read_state_version"`
			UserGuildSettingsVersion    int                    `json:"user_guild_settings_version"`
			PrivateChannelsVersion      string                 `json:"private_channels_version"`
			ApiCodeVersion              int                    `json:"api_code_version"`
		} `json:"client_state"`
	} `json:"d"`
}

func getIdentifyPayload(token string) IdentifyPayload {
	return IdentifyPayload{
		Op: 2,
		D: struct {
			Token         string `json:"token"`
			Capabilities  int    `json:"capabilities"`
			Properties    struct {
				Os                    string `json:"os"`
				Browser              string `json:"browser"`
				Device               string `json:"device"`
				SystemLocale         string `json:"system_locale"`
				BrowserUserAgent     string `json:"browser_user_agent"`
				BrowserVersion       string `json:"browser_version"`
				OsVersion            string `json:"os_version"`
				Referrer             string `json:"referrer"`
				ReferringDomain      string `json:"referring_domain"`
				ReferrerCurrent      string `json:"referrer_current"`
				ReferringDomainCurrent string `json:"referring_domain_current"`
				ReleaseChannel       string `json:"release_channel"`
				ClientBuildNumber    int    `json:"client_build_number"`
				ClientEventSource    *int   `json:"client_event_source"`
			} `json:"properties"`
			Presence struct {
				Status string        `json:"status"`
				Since  int           `json:"since"`
				Activities []interface{} `json:"activities"`
				Afk     bool         `json:"afk"`
			} `json:"presence"`
			Compress     bool `json:"compress"`
			ClientState  struct {
				GuildVersions                map[string]interface{} `json:"guild_versions"`
				HighestLastMessageID        string                 `json:"highest_last_message_id"`
				ReadStateVersion            int                    `json:"read_state_version"`
				UserGuildSettingsVersion    int                    `json:"user_guild_settings_version"`
				PrivateChannelsVersion      string                 `json:"private_channels_version"`
				ApiCodeVersion              int                    `json:"api_code_version"`
			} `json:"client_state"`
		}{
			Token:         token,
			Capabilities:  16381,
			Properties: struct {
				Os                    string `json:"os"`
				Browser              string `json:"browser"`
				Device               string `json:"device"`
				SystemLocale         string `json:"system_locale"`
				BrowserUserAgent     string `json:"browser_user_agent"`
				BrowserVersion       string `json:"browser_version"`
				OsVersion            string `json:"os_version"`
				Referrer             string `json:"referrer"`
				ReferringDomain      string `json:"referring_domain"`
				ReferrerCurrent      string `json:"referrer_current"`
				ReferringDomainCurrent string `json:"referring_domain_current"`
				ReleaseChannel       string `json:"release_channel"`
				ClientBuildNumber    int    `json:"client_build_number"`
				ClientEventSource    *int   `json:"client_event_source"`
			}{
				Os:                    "Android",
				Browser:              "Discord Android",
				Device:               "Android",
				SystemLocale:         "ja-JP",
				BrowserUserAgent:     "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
				BrowserVersion:       "122.0.0.0",
				OsVersion:            "",
				Referrer:             "",
				ReferringDomain:      "",
				ReferrerCurrent:      "",
				ReferringDomainCurrent: "",
				ReleaseChannel:       "stable",
				ClientBuildNumber:    263582,
				ClientEventSource:    nil,
			},
			Presence: struct {
				Status string        `json:"status"`
				Since  int           `json:"since"`
				Activities []interface{} `json:"activities"`
				Afk     bool         `json:"afk"`
			}{
				Status:    "invisible",
				Since:     0,
				Activities: []interface{}{},
				Afk:       false,
			},
			Compress:     false,
			ClientState: struct {
				GuildVersions                map[string]interface{} `json:"guild_versions"`
				HighestLastMessageID        string                 `json:"highest_last_message_id"`
				ReadStateVersion            int                    `json:"read_state_version"`
				UserGuildSettingsVersion    int                    `json:"user_guild_settings_version"`
				PrivateChannelsVersion      string                 `json:"private_channels_version"`
				ApiCodeVersion              int                    `json:"api_code_version"`
			}{
				GuildVersions:                map[string]interface{}{},
				HighestLastMessageID:         "0",
				ReadStateVersion:            0,
				UserGuildSettingsVersion:     -1,
				PrivateChannelsVersion:      "0",
				ApiCodeVersion:              0,
			},
		},
	}
}

type RequestPayload struct {
	Op int `json:"op"`
	D struct {
		GuildID  string `json:"guild_id"`
		Typing   bool   `json:"typing"`
		Activities bool `json:"activities"`
		Threads   bool   `json:"threads"`
		Channels  map[string][][]int `json:"channels"`
	} `json:"d"`
}

func getRequestPayload(serverID, channelID string, start, end int) RequestPayload {
	return RequestPayload{
		Op: 14,
		D: struct {
			GuildID  string `json:"guild_id"`
			Typing   bool   `json:"typing"`
			Activities bool `json:"activities"`
			Threads   bool   `json:"threads"`
			Channels  map[string][][]int `json:"channels"`
		}{
			GuildID:    serverID,
			Typing:     true,
			Activities: true,
			Threads:    true,
			Channels:   map[string][][]int{channelID: {{start, end}}},
		},
	}
}

func extractUserIDs(response map[string]interface{}) []string {
	users := []string{}
	ops := response["d"].(map[string]interface{})["ops"].([]interface{})
	for _, op := range ops {
		items := op.(map[string]interface{})["items"].([]interface{})
		for _, item := range items {
			if member, ok := item.(map[string]interface{})["member"]; ok {
				user := member.(map[string]interface{})["user"].(map[string]interface{})
				users = append(users, user["id"].(string))
			}
		}
	}
	return users
}

func getMembers(serverID, channelID, token string) ([]string, error) {
	uri := "wss://gateway.discord.gg/?v=10&encoding=json"
	c, _, err := websocket.DefaultDialer.Dial(uri, nil)
	if err != nil {
		return nil, err
	}
	defer c.Close()

	err = c.WriteJSON(getIdentifyPayload(token))
	if err != nil {
		return nil, err
	}

	users := []string{}
	chunkSize := 100
	start := 0

	for {
		err = c.WriteJSON(getRequestPayload(serverID, channelID, start, start+chunkSize-1))
		if err != nil {
			return nil, err
		}

		_, message, err := c.ReadMessage()
		if err != nil {
			return nil, err
		}

		var response map[string]interface{}
		err = json.Unmarshal(message, &response)
		if err != nil {
			return nil, err
		}

		if response["t"] == "GUILD_MEMBER_LIST_UPDATE" {
			chunkUsers := extractUserIDs(response)
			if len(chunkUsers) == 0 {
				break
			}
			users = append(users, chunkUsers...)
			start += chunkSize
		}
	}

	return users, nil
}

func insertUserData(userID, userBio, avatar, banner string, accentColor int, connectedAccounts []map[string]interface{}, linkedWebsites []string) error {
	dbMutex.Lock()
	defer dbMutex.Unlock()

	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	_, err = tx.Exec("INSERT OR REPLACE INTO users (userid, bio, avatar, banner, accent_color) VALUES (?, ?, ?, ?, ?)", userID, userBio, avatar, banner, accentColor)
	if err != nil {
		return err
	}

	for _, account := range connectedAccounts {
		_, err = tx.Exec("INSERT INTO linked_accounts (userid, account_type, username, website) VALUES (?, ?, ?, ?)",
			userID, account["type"], account["name"], nil)
		if err != nil {
			return err
		}
	}

	for _, site := range linkedWebsites {
		_, err = tx.Exec("INSERT INTO linked_accounts (userid, account_type, username, website) VALUES (?, ?, ?, ?)",
			userID, nil, nil, site)
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}

func searchByUserID(userID string) (sql.NullString, []map[string]interface{}, error) {
	var user sql.NullString
	var accounts []map[string]interface{}

	row := db.QueryRow("SELECT * FROM users WHERE userid = ?", userID)
	err := row.Scan(&user)
	if err != nil && err != sql.ErrNoRows {
		return user, nil, err
	}

	rows, err := db.Query("SELECT * FROM linked_accounts WHERE userid = ?", userID)
	if err != nil {
		return user, nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var account map[string]interface{}
		err := rows.Scan(&account)
		if err != nil {
			return user, nil, err
		}
		accounts = append(accounts, account)
	}

	return user, accounts, nil
}

func searchByAccount(accountType, username string) ([]map[string]interface{}, error) {
	query := `
	SELECT users.userid, users.bio, linked_accounts.account_type, linked_accounts.username, linked_accounts.website
	FROM linked_accounts
	JOIN users ON linked_accounts.userid = users.userid
	WHERE linked_accounts.account_type = ? AND linked_accounts.username = ?
	`
	rows, err := db.Query(query, accountType, username)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []map[string]interface{}
	for rows.Next() {
		var result map[string]interface{}
		err := rows.Scan(&result)
		if err != nil {
			return nil, err
		}
		results = append(results, result)
	}

	return results, nil
}

func fetchAndStoreUserData(token, userID string, wg *sync.WaitGroup) {
	defer wg.Done()
	profileData, err := getUserProfile(token, userID)
	if err != nil {
		log.Printf("Error fetching user profile for user %s: %v", userID, err)
		return
	}

	userData := profileData["user"].(map[string]interface{})
	userBio := userData["bio"].(string)
	avatar := userData["avatar"].(string)
	banner := userData["banner"].(string)
	accentColor := int(userData["accent_color"].(float64))
	connectedAccounts := profileData["connected_accounts"].([]interface{})
	linkedWebsites := []string{}
	for _, account := range connectedAccounts {
		if account.(map[string]interface{})["type"] == "domain" {
			linkedWebsites = append(linkedWebsites, account.(map[string]interface{})["name"].(string))
		}
	}

	err = insertUserData(userID, userBio, avatar, banner, accentColor, connectedAccounts, linkedWebsites)
	if err != nil {
		log.Printf("Error inserting user data for user %s: %v", userID, err)
		return
	}

	fmt.Printf("Stored data for user %s\n", userID)
}

func worker(jobs <-chan string, results chan<- string, token string, wg *sync.WaitGroup) {
	defer wg.Done()
	for userID := range jobs {
		fetchAndStoreUserData(token, userID, wg)
		results <- userID
	}
}

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatalf("Error loading .env file: %v", err)
	}

	if len(os.Args) != 4 {
		fmt.Println("Usage: go run discord_scraper.go <serverid> <channelid> <token>")
		return
	}

	serverID := os.Args[1]
	channelID := os.Args[2]
	token := os.Args[3]
	fmt.Printf("Server ID: %s\n", serverID)
	fmt.Printf("Channel ID: %s\n", channelID)
	fmt.Printf("Token: %s\n", token)

	initializeDB()
	defer db.Close()

	statusCode, err := checkToken(token)
	if err != nil {
		log.Fatalf("Error checking token: %v", err)
	}
	if statusCode != http.StatusOK {
		fmt.Printf("[INVALID] %s [%d]\n", token, statusCode)
		os.Exit(1)
	}
	fmt.Printf("[VALID] %s [%d]\n", token, statusCode)

	fmt.Printf("Scraping members in server %s\n", serverID)
	members, err := getMembers(serverID, channelID, token)
	if err != nil {
		log.Fatalf("Failed to scrape members: %v", err)
	}
	fmt.Printf("Successfully scraped %d members\n", len(members))

	fmt.Println("\nFetching user profiles and storing in database...")
	var wg sync.WaitGroup
	jobs := make(chan string, len(members))
	results := make(chan string, len(members))
	numWorkers := 10

	for w := 1; w <= numWorkers; w++ {
		wg.Add(1)
		go worker(jobs, results, token, &wg)
	}

	for _, userID := range members {
		jobs <- userID
	}
	close(jobs)

	wg.Wait()
	close(results)

	fmt.Println("\nAll data has been successfully scraped and stored in the database!")
	fmt.Println("\nYou can now use the following functions to query the database:")
	fmt.Println("1. searchByUserID(userid)")
	fmt.Println("2. searchByAccount(account_type, username)")
}
