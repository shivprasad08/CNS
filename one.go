package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Result holds the scraping result for a URL
type Result struct {
	URL   string `json:"url"`
	Title string `json:"title"`
	Error string `json:"error,omitempty"`
}

// Job represents a scraping job
type Job struct {
	URL string
	ID  int
}

// WebScraper manages concurrent web scraping
type WebScraper struct {
	workers int
	timeout time.Duration
}

// NewWebScraper creates a new scraper instance
func NewWebScraper(workers int, timeout time.Duration) *WebScraper {
	return &WebScraper{
		workers: workers,
		timeout: timeout,
	}
}

// extractTitle extracts the title from HTML content
func extractTitle(html string) string {
	re := regexp.MustCompile(`(?i)<title[^>]*>(.*?)</title>`)
	matches := re.FindStringSubmatch(html)
	if len(matches) > 1 {
		return strings.TrimSpace(matches[1])
	}
	return "No title found"
}

// fetchURL fetches a URL and extracts its title
func (ws *WebScraper) fetchURL(url string) Result {
	client := &http.Client{
		Timeout: ws.timeout,
	}

	resp, err := client.Get(url)
	if err != nil {
		return Result{URL: url, Error: err.Error()}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return Result{URL: url, Error: fmt.Sprintf("Status code: %d", resp.StatusCode)}
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return Result{URL: url, Error: err.Error()}
	}

	title := extractTitle(string(body))
	return Result{URL: url, Title: title}
}

// worker processes jobs from the jobs channel
func (ws *WebScraper) worker(id int, jobs <-chan Job, results chan<- Result, wg *sync.WaitGroup) {
	defer wg.Done()
	for job := range jobs {
		fmt.Printf("[Worker %d] Processing: %s\n", id, job.URL)
		result := ws.fetchURL(job.URL)
		results <- result
	}
	fmt.Printf("[Worker %d] Finished\n", id)
}

// ScrapeURLs scrapes multiple URLs concurrently using worker pool
func (ws *WebScraper) ScrapeURLs(urls []string) []Result {
	numJobs := len(urls)
	jobs := make(chan Job, numJobs)
	results := make(chan Result, numJobs)

	var wg sync.WaitGroup

	// Start workers
	for i := 1; i <= ws.workers; i++ {
		wg.Add(1)
		go ws.worker(i, jobs, results, &wg)
	}

	// Send jobs
	for i, url := range urls {
		jobs <- Job{URL: url, ID: i + 1}
	}
	close(jobs)

	// Close results channel when all workers are done
	go func() {
		wg.Wait()
		close(results)
	}()

	// Collect results
	var allResults []Result
	for result := range results {
		allResults = append(allResults, result)
	}

	return allResults
}

// REST API Server
type APIServer struct {
	scraper *WebScraper
	port    string
}

// NewAPIServer creates a new API server
func NewAPIServer(scraper *WebScraper, port string) *APIServer {
	return &APIServer{
		scraper: scraper,
		port:    port,
	}
}

// ScrapeRequest represents the API request body
type ScrapeRequest struct {
	URLs []string `json:"urls"`
}

// handleScrape handles POST /scrape endpoint
func (api *APIServer) handleScrape(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req ScrapeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if len(req.URLs) == 0 {
		http.Error(w, "No URLs provided", http.StatusBadRequest)
		return
	}

	results := api.scraper.ScrapeURLs(req.URLs)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"count":   len(results),
		"results": results,
	})
}

// handleHealth handles GET /health endpoint
func (api *APIServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status": "healthy",
		"time":   time.Now().Format(time.RFC3339),
	})
}

// Start starts the HTTP server
func (api *APIServer) Start() {
	http.HandleFunc("/scrape", api.handleScrape)
	http.HandleFunc("/health", api.handleHealth)

	fmt.Printf("\n🚀 API Server started on http://localhost%s\n", api.port)
	fmt.Println("Endpoints:")
	fmt.Printf("  POST http://localhost%s/scrape - Scrape URLs\n", api.port)
	fmt.Printf("  GET  http://localhost%s/health - Health check\n\n", api.port)

	if err := http.ListenAndServe(api.port, nil); err != nil {
		fmt.Printf("Server error: %v\n", err)
	}
}

// Menu functions
func clearScreen() {
	fmt.Print("\033[H\033[2J")
}

func displayMenu() {
	fmt.Println("\n╔════════════════════════════════════════════╗")
	fmt.Println("║     CONCURRENT WEB SCRAPER MENU            ║")
	fmt.Println("╚════════════════════════════════════════════╝")
	fmt.Println("1. Scrape URLs (Interactive)")
	fmt.Println("2. Scrape Predefined URLs")
	fmt.Println("3. Start REST API Server")
	fmt.Println("4. Configure Settings")
	fmt.Println("5. Exit")
	fmt.Print("\nEnter your choice: ")
}

func readInput(reader *bufio.Reader) string {
	input, _ := reader.ReadString('\n')
	return strings.TrimSpace(input)
}

func scrapeInteractive(scraper *WebScraper, reader *bufio.Reader) {
	fmt.Println("\n--- Interactive URL Scraping ---")
	fmt.Println("Enter URLs (one per line). Type 'done' when finished:")

	var urls []string
	for {
		fmt.Print("> ")
		url := readInput(reader)
		if url == "done" {
			break
		}
		if url != "" {
			urls = append(urls, url)
		}
	}

	if len(urls) == 0 {
		fmt.Println("❌ No URLs provided!")
		return
	}

	fmt.Printf("\n🔄 Scraping %d URLs with %d workers...\n\n", len(urls), scraper.workers)
	start := time.Now()
	results := scraper.ScrapeURLs(urls)
	elapsed := time.Since(start)

	displayResults(results, elapsed)
}

func scrapePredefined(scraper *WebScraper) {
	urls := []string{
		"https://www.golang.org",
		"https://www.github.com",
		"https://www.stackoverflow.com",
		"https://www.reddit.com",
		"https://www.wikipedia.org",
	}

	fmt.Printf("\n🔄 Scraping %d predefined URLs...\n\n", len(urls))
	start := time.Now()
	results := scraper.ScrapeURLs(urls)
	elapsed := time.Since(start)

	displayResults(results, elapsed)
}

func displayResults(results []Result, elapsed time.Duration) {
	fmt.Println("\n╔════════════════════════════════════════════╗")
	fmt.Println("║              SCRAPING RESULTS              ║")
	fmt.Println("╚════════════════════════════════════════════╝")

	for i, result := range results {
		fmt.Printf("\n[%d] URL: %s\n", i+1, result.URL)
		if result.Error != "" {
			fmt.Printf("    ❌ Error: %s\n", result.Error)
		} else {
			fmt.Printf("    ✅ Title: %s\n", result.Title)
		}
	}

	fmt.Printf("\n⏱️  Total time: %v\n", elapsed)
	fmt.Printf("📊 Success: %d/%d\n", countSuccessful(results), len(results))
}

func countSuccessful(results []Result) int {
	count := 0
	for _, r := range results {
		if r.Error == "" {
			count++
		}
	}
	return count
}

func configureSettings(scraper *WebScraper, reader *bufio.Reader) {
	fmt.Println("\n--- Configuration ---")
	fmt.Printf("Current workers: %d\n", scraper.workers)
	fmt.Printf("Current timeout: %v\n", scraper.timeout)

	fmt.Print("\nEnter number of workers (1-20): ")
	var workers int
	fmt.Scanf("%d", &workers)
	if workers >= 1 && workers <= 20 {
		scraper.workers = workers
		fmt.Println("✅ Workers updated!")
	}

	fmt.Print("Enter timeout in seconds (1-60): ")
	var timeout int
	fmt.Scanf("%d", &timeout)
	if timeout >= 1 && timeout <= 60 {
		scraper.timeout = time.Duration(timeout) * time.Second
		fmt.Println("✅ Timeout updated!")
	}

	// Clear input buffer
	reader.ReadString('\n')
}

func main() {
	scraper := NewWebScraper(3, 10*time.Second)
	reader := bufio.NewReader(os.Stdin)

	for {
		displayMenu()
		choice := readInput(reader)

		switch choice {
		case "1":
			scrapeInteractive(scraper, reader)
		case "2":
			scrapePredefined(scraper)
		case "3":
			api := NewAPIServer(scraper, ":8080")
			api.Start()
		case "4":
			configureSettings(scraper, reader)
		case "5":
			fmt.Println("\n👋 Goodbye!")
			return
		default:
			fmt.Println("\n❌ Invalid choice! Please try again.")
		}

		if choice != "3" {
			fmt.Print("\nPress Enter to continue...")
			reader.ReadString('\n')
		}
	}
}