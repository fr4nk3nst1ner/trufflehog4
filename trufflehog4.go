package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const (
	baseURL           = "https://api.github.com"
	postmanAPIBaseURL = "https://api.getpostman.com"
)

// GitHubMember represents a GitHub organization member
type GitHubMember struct {
	Login string `json:"login"`
}

// GitHubRepo represents a GitHub repository
type GitHubRepo struct {
	Name       string    `json:"name"`
	CloneURL   string    `json:"clone_url"`
	Fork       bool      `json:"fork"`
	Private    bool      `json:"private"`
	Size       int       `json:"size"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// PostmanWorkspace represents a Postman workspace
type PostmanWorkspace struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// PostmanWorkspacesResponse represents the response from Postman API
type PostmanWorkspacesResponse struct {
	Workspaces []PostmanWorkspace `json:"workspaces"`
}

// Config holds the command-line arguments
type Config struct {
	command       string
	githubOrg     string
	maxRepoSize   int
	token         string
	user          string
	repo          string
	userListFile  string
	getUsersFile  string
	clone         bool
	trufflehog   bool
	verify        bool
	onlyVerified bool
	noFork       bool
	timeLimit    int
	retainImage  bool
	extractLayers string
	scanOrg      string
	search       string
	v1Convert    bool
	workspaceID  string
}

// DockerHubRepository represents a Docker Hub repository
type DockerHubRepository struct {
	Name string `json:"name"`
}

// DockerHubResponse represents the response from Docker Hub API
type DockerHubResponse struct {
	Results []DockerHubRepository `json:"results"`
	Next    string               `json:"next"`
}

// DockerHubTag represents a Docker Hub tag
type DockerHubTag struct {
	Name string `json:"name"`
}

// DockerHubTagResponse represents the response from Docker Hub tags API
type DockerHubTagResponse struct {
	Results []DockerHubTag `json:"results"`
	Next    string        `json:"next"`
}

func getOrgMembers(orgName, token string, outputFile string) ([]string, error) {
	url := fmt.Sprintf("%s/orgs/%s/members", baseURL, orgName)
	members := []string{}
	page := 1

	client := &http.Client{}

	for {
		req, err := http.NewRequest("GET", fmt.Sprintf("%s?per_page=100&page=%d", url, page), nil)
		if err != nil {
			return nil, fmt.Errorf("error creating request: %v", err)
		}

		if token != "" {
			req.Header.Set("Authorization", "token "+token)
		}

		resp, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("error making request: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("API request failed with status: %d", resp.StatusCode)
		}

		var memberList []GitHubMember
		if err := json.NewDecoder(resp.Body).Decode(&memberList); err != nil {
			return nil, fmt.Errorf("error decoding response: %v", err)
		}

		if len(memberList) == 0 {
			break
		}

		for _, member := range memberList {
			members = append(members, member.Login)
		}

		if resp.Header.Get("Link") == "" {
			break
		}

		page++
	}

	if outputFile != "" {
		content := strings.Join(members, "\n")
		if err := ioutil.WriteFile(outputFile, []byte(content), 0644); err != nil {
			return nil, fmt.Errorf("error writing to file: %v", err)
		}
	}

	return members, nil
}

func runTrufflehog(repos []string, username string, verify, onlyVerified bool, token string) error {
	for _, repoURL := range repos {
		repoName := strings.TrimSuffix(filepath.Base(repoURL), ".git")
		fmt.Printf("Running trufflehog on %s for user %s...\n", repoName, username)

		args := []string{"github", "--repo", repoURL}
		if onlyVerified {
			args = append(args, "--only-verified")
		} else if !verify {
			args = append(args, "--no-verification")
		}

		if token != "" {
			args = append(args, "--token", token)
		}

		cmd := exec.Command("trufflehog", args...)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr

		if err := cmd.Run(); err != nil {
			fmt.Printf("Error running trufflehog on %s: %v\n", repoURL, err)
		}
	}
	return nil
}

func main() {
	config := parseFlags()

	switch config.command {
	case "github":
		if !config.clone && !config.trufflehog {
			fmt.Println("Either --clone or --trufflehog must be specified for 'github' command")
			os.Exit(1)
		}
		if err := githubMain(config); err != nil {
			fmt.Printf("Error in github command: %v\n", err)
			os.Exit(1)
		}
	case "ghcr":
		if config.githubOrg == "" && config.userListFile == "" && config.user == "" && config.repo == "" {
			fmt.Println("Either --github-org, --user, or --user-list must be specified for 'ghcr' command")
			os.Exit(1)
		}
		if err := ghcrMain(config); err != nil {
			fmt.Printf("Error in ghcr command: %v\n", err)
			os.Exit(1)
		}
	case "postman":
		if config.token == "" {
			fmt.Println("--token is required for 'postman'")
			os.Exit(1)
		}
		if err := postmanMain(config); err != nil {
			fmt.Printf("Error in postman command: %v\n", err)
			os.Exit(1)
		}
	case "docker":
		if err := dockerMain(config); err != nil {
			fmt.Printf("Error in docker command: %v\n", err)
			os.Exit(1)
		}
	default:
		fmt.Printf("Unknown command: %s\n", config.command)
		os.Exit(1)
	}
}

func parseFlags() *Config {
	config := &Config{}

	// Create a new FlagSet to handle flags
	cmdFlags := flag.NewFlagSet(os.Args[0], flag.ExitOnError)

	// Add usage information
	cmdFlags.Usage = func() {
		fmt.Printf(`TruffleHog Wrapper - A tool for scanning repositories and containers

Usage: go run trufflehogWrapper.go <command> [options]

Commands:
  github   Scan GitHub repositories
  ghcr     Scan GitHub Container Registry images
  docker   Scan Docker Hub images
  postman  Scan Postman workspaces

Options:
`, os.Args[0])
		cmdFlags.PrintDefaults()
		fmt.Println("\nExamples:")
		fmt.Println("  Scan GitHub org:           trufflehogWrapper github --github-org myorg --trufflehog")
		fmt.Println("  Scan Docker Hub:           trufflehogWrapper docker --scan-org myorg")
		fmt.Println("  Scan GitHub containers:    trufflehogWrapper ghcr --github-org myorg")
		fmt.Println("  Scan Postman workspaces:   trufflehogWrapper postman --token mytoken")
	}

	// Define command-line flags
	cmdFlags.StringVar(&config.githubOrg, "github-org", "", "Name of the GitHub organization")
	cmdFlags.IntVar(&config.maxRepoSize, "max-repo-size", 0, "Maximum repository size in MB")
	cmdFlags.StringVar(&config.token, "token", "", "GitHub Personal Access Token")
	cmdFlags.StringVar(&config.user, "user", "", "Process repositories for a specific user")
	cmdFlags.StringVar(&config.repo, "repo", "", "Process a specific repository URL")
	cmdFlags.StringVar(&config.userListFile, "user-list", "", "File with a list of usernames to process")
	cmdFlags.StringVar(&config.getUsersFile, "get-users", "", "File to save the list of organization members")
	cmdFlags.BoolVar(&config.clone, "clone", false, "Clone the repositories")
	cmdFlags.BoolVar(&config.trufflehog, "trufflehog", false, "Run trufflehog on the repositories")
	cmdFlags.BoolVar(&config.verify, "verify", false, "Run trufflehog with verification")
	cmdFlags.BoolVar(&config.onlyVerified, "only-verified", false, "Run trufflehog with --only-verified option")
	cmdFlags.BoolVar(&config.noFork, "no-fork", false, "Exclude forked repositories")
	cmdFlags.IntVar(&config.timeLimit, "time-limit", 0, "Limit repositories to those updated within the last N years")
	cmdFlags.BoolVar(&config.retainImage, "retain-image", false, "Retain the Docker image after scanning")
	cmdFlags.StringVar(&config.extractLayers, "extract-layers", "", "Directory to extract Docker image layers")
	cmdFlags.StringVar(&config.scanOrg, "scan-org", "", "Scan all repositories for the specified GitHub organization")
	cmdFlags.StringVar(&config.search, "search", "", "Search query for Postman workspaces")
	cmdFlags.BoolVar(&config.v1Convert, "v1", false, "Convert Docker images using deprecated Schema 1 format")
	cmdFlags.StringVar(&config.workspaceID, "workspace-id", "", "Specific Postman workspace ID to scan")

	// Check if help is requested
	if len(os.Args) > 1 && (os.Args[1] == "-h" || os.Args[1] == "--help" || os.Args[1] == "help") {
		cmdFlags.Usage()
		os.Exit(0)
	}

	// Check if we have any arguments
	if len(os.Args) < 2 {
		fmt.Println("No command specified")
		cmdFlags.Usage()
		os.Exit(1)
	}

	// Set the command (first argument)
	config.command = os.Args[1]

	// Parse the remaining arguments (skip program name and command)
	if err := cmdFlags.Parse(os.Args[2:]); err != nil {
		fmt.Printf("Error parsing flags: %v\n", err)
		os.Exit(1)
	}

	return config
}

func getUserPublicRepos(username string, token string, maxRepoSizeKB int, noFork bool, timeLimit int) ([]string, error) {
	url := fmt.Sprintf("%s/users/%s/repos", baseURL, username)
	repos := []string{}
	page := 1
	client := &http.Client{}

	// Calculate cutoff date if timeLimit is specified
	var cutoffDate time.Time
	if timeLimit > 0 {
		cutoffDate = time.Now().AddDate(-timeLimit, 0, 0)
	}

	for {
		req, err := http.NewRequest("GET", fmt.Sprintf("%s?page=%d&per_page=100", url, page), nil)
		if err != nil {
			return nil, fmt.Errorf("error creating request: %v", err)
		}

		if token != "" {
			req.Header.Set("Authorization", "token "+token)
		}

		resp, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("error making request: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("API request failed with status: %d", resp.StatusCode)
		}

		var repoList []GitHubRepo
		if err := json.NewDecoder(resp.Body).Decode(&repoList); err != nil {
			return nil, fmt.Errorf("error decoding response: %v", err)
		}

		if len(repoList) == 0 {
			break
		}

		for _, repo := range repoList {
			// Skip forked repos if noFork is true
			if noFork && repo.Fork {
				fmt.Printf("Skipping forked repo %s for user %s\n", repo.Name, username)
				continue
			}

			// Skip repos older than cutoff date if timeLimit is specified
			if timeLimit > 0 && repo.UpdatedAt.Before(cutoffDate) {
				fmt.Printf("Skipping old repo %s (last updated: %s) for user %s\n", 
					repo.Name, repo.UpdatedAt.Format("2006-01-02"), username)
				continue
			}

			// Check repo size if maxRepoSizeKB is specified
			if !repo.Private && (maxRepoSizeKB == 0 || repo.Size <= maxRepoSizeKB) {
				repos = append(repos, repo.CloneURL)
			} else if maxRepoSizeKB > 0 && repo.Size > maxRepoSizeKB {
				fmt.Printf("Skipping %s for user %s (size: %.2f MB)\n", 
					repo.Name, username, float64(repo.Size)/1000)
			}
		}

		if resp.Header.Get("Link") == "" {
			break
		}
		page++
	}

	sizeInfo := "of any size"
	if maxRepoSizeKB > 0 {
		sizeInfo = fmt.Sprintf("under %.2f MB", float64(maxRepoSizeKB)/1000)
	}
	fmt.Printf("Found %d public repositories %s for user %s.\n", len(repos), sizeInfo, username)
	return repos, nil
}

func getUserRepos(username, token string) ([]string, error) {
	url := fmt.Sprintf("%s/users/%s/repos", baseURL, username)
	client := &http.Client{}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("error creating request: %v", err)
	}

	if token != "" {
		req.Header.Set("Authorization", "token "+token)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error making request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API request failed with status: %d", resp.StatusCode)
	}

	var repos []GitHubRepo
	if err := json.NewDecoder(resp.Body).Decode(&repos); err != nil {
		return nil, fmt.Errorf("error decoding response: %v", err)
	}

	cloneURLs := make([]string, len(repos))
	for i, repo := range repos {
		cloneURLs[i] = repo.CloneURL
	}

	return cloneURLs, nil
}

func getPublicRepos(orgName, token string) ([]string, error) {
	url := fmt.Sprintf("%s/orgs/%s/repos", baseURL, orgName)
	repos := []string{}
	page := 1
	client := &http.Client{}

	for {
		req, err := http.NewRequest("GET", fmt.Sprintf("%s?page=%d&per_page=100&type=public", url, page), nil)
		if err != nil {
			return nil, fmt.Errorf("error creating request: %v", err)
		}

		if token != "" {
			req.Header.Set("Authorization", fmt.Sprintf("token %s", token))
		}
		req.Header.Set("Accept", "application/vnd.github.v3+json")

		resp, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("error making request: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			body, _ := ioutil.ReadAll(resp.Body)
			return nil, fmt.Errorf("API request failed with status: %d, body: %s", resp.StatusCode, string(body))
		}

		var repoList []GitHubRepo
		if err := json.NewDecoder(resp.Body).Decode(&repoList); err != nil {
			return nil, fmt.Errorf("error decoding response: %v", err)
		}

		if len(repoList) == 0 {
			break
		}

		for _, repo := range repoList {
			if !repo.Private {  // Only include public repositories
				repos = append(repos, repo.Name)
			}
		}

		// Check for next page
		if resp.Header.Get("Link") == "" || !strings.Contains(resp.Header.Get("Link"), "next") {
			break
		}
		page++
	}

	fmt.Printf("Found %d public repositories for organization %s.\n", len(repos), orgName)
	return repos, nil
}

func githubMain(config *Config) error {
	// Process specific repo if provided
	if config.repo != "" {
		fmt.Printf("Processing specific repo: %s\n", config.repo)
		return runTrufflehog([]string{config.repo}, "specified-repo", config.verify, config.onlyVerified, config.token)
	}

	// Process repositories for a specific user
	if config.user != "" {
		fmt.Printf("Processing repositories for user: %s\n", config.user)
		repos, err := getUserRepos(config.user, config.token)
		if err != nil {
			return fmt.Errorf("error getting user repositories: %v", err)
		}
		return runTrufflehog(repos, config.user, config.verify, config.onlyVerified, config.token)
	}

	// Process organization repositories
	if config.githubOrg != "" {
		fmt.Printf("Scanning repositories for organization: %s\n", config.githubOrg)
		repos, err := getPublicRepos(config.githubOrg, config.token)
		if err != nil {
			return fmt.Errorf("error getting organization repositories: %v", err)
		}

		if len(repos) == 0 {
			fmt.Printf("No repositories found for organization: %s\n", config.githubOrg)
			return nil
		}

		// Convert repo names to full URLs
		repoURLs := make([]string, len(repos))
		for i, repo := range repos {
			repoURLs[i] = fmt.Sprintf("https://github.com/%s/%s.git", config.githubOrg, repo)
		}

		fmt.Printf("Found %d repositories to scan\n", len(repoURLs))
		return runTrufflehog(repoURLs, config.githubOrg, config.verify, config.onlyVerified, config.token)
	}

	// Process user list if provided
	if config.userListFile != "" {
		content, err := ioutil.ReadFile(config.userListFile)
		if err != nil {
			return fmt.Errorf("error reading user list file: %v", err)
		}
		members := strings.Split(strings.TrimSpace(string(content)), "\n")
		fmt.Printf("Using user list from %s\n", config.userListFile)

		for _, username := range members {
			fmt.Printf("\nGetting public repos for user %s...\n", username)
			repos, err := getUserPublicRepos(username, config.token, config.maxRepoSize*1000, config.noFork, config.timeLimit)
			if err != nil {
				fmt.Printf("Error getting repositories for user %s: %v\n", username, err)
				continue
			}

			if config.trufflehog {
				if err := runTrufflehog(repos, username, config.verify, config.onlyVerified, config.token); err != nil {
					fmt.Printf("Error running trufflehog for user %s: %v\n", username, err)
				}
			}
		}
		return nil
	}

	return fmt.Errorf("either --github-org, --user, --repo, or --user-list must be specified")
}

func dockerLogin(registry, username, token string) error {
	if username == "" || token == "" {
		return fmt.Errorf("invalid credentials: username=%s, token=<redacted>", username)
	}

	fmt.Printf("Logging in to %s as %s...\n", registry, username)
	cmd := exec.Command("docker", "login", registry, "-u", username, "--password-stdin")
	cmd.Stdin = strings.NewReader(token)
	
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to log in to %s: %v", registry, err)
	}
	
	fmt.Println("Login succeeded!")
	return nil
}

func scanDockerImage(imageName string, verify bool, useDockle bool) error {
	var cmd *exec.Cmd
	
	if useDockle {
		fmt.Printf("Scanning image with Dockle: %s\n", imageName)
		cmd = exec.Command("dockle", imageName)
	} else {
		fmt.Printf("Scanning image with TruffleHog: %s\n", imageName)
		args := []string{"docker", "--image", imageName}
		if verify {
			args = append(args, "--verify")
		} else {
			args = append(args, "--no-verification")
		}
		cmd = exec.Command("trufflehog", args...)
	}

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func deleteDockerImage(imageName string) error {
	fmt.Printf("Deleting image: %s\n", imageName)
	cmd := exec.Command("docker", "rmi", imageName)
	if err := cmd.Run(); err != nil {
		if strings.Contains(err.Error(), "No such image") {
			fmt.Printf("Image %s does not exist. Skipping deletion.\n", imageName)
			return nil
		}
		return fmt.Errorf("failed to delete image %s: %v", imageName, err)
	}
	fmt.Printf("Image %s deleted successfully!\n", imageName)
	return nil
}

func ghcrMain(config *Config) error {
	username := config.user
	if username == "" && config.repo != "" {
		parts := strings.Split(config.repo, "/")
		if len(parts) >= 2 {
			username = parts[len(parts)-2]
		}
	}
	if username == "" {
		username = config.githubOrg
	}
	if username == "" {
		return fmt.Errorf("a valid username or organization must be provided for authentication")
	}

	if config.token != "" {
		if err := dockerLogin("ghcr.io", username, config.token); err != nil {
			return err
		}
	}

	// Handle specific repository
	if config.repo != "" {
		parts := strings.Split(strings.TrimRight(config.repo, "/"), "/")
		if len(parts) < 2 {
			return fmt.Errorf("invalid repository URL: %s", config.repo)
		}
		repoName := parts[len(parts)-1]
		userName := parts[len(parts)-2]
		imageName := fmt.Sprintf("ghcr.io/%s/%s:latest", userName, repoName)
		return processImage(imageName, config)
	}

	// Handle organization-wide scanning
	if config.githubOrg != "" {
		fmt.Printf("Scanning GitHub Container Registry for organization: %s\n", config.githubOrg)
		repos, err := getPublicRepos(config.githubOrg, config.token)
		if err != nil {
			return fmt.Errorf("error getting organization repositories: %v", err)
		}

		if len(repos) == 0 {
			fmt.Printf("No repositories found for organization: %s\n", config.githubOrg)
			return nil
		}

		fmt.Printf("Found %d repositories to scan\n", len(repos))
		for _, repo := range repos {
			imageName := fmt.Sprintf("ghcr.io/%s/%s:latest", config.githubOrg, repo)
			fmt.Printf("Processing image: %s\n", imageName)
			if err := processImage(imageName, config); err != nil {
				// Log error but continue with other repositories
				fmt.Printf("Error processing %s: %v\n", imageName, err)
			}
		}
		return nil
	}

	// Handle user repositories
	if config.user != "" {
		fmt.Printf("Scanning GitHub Container Registry for user: %s\n", config.user)
		repos, err := getUserRepos(config.user, config.token)
		if err != nil {
			return fmt.Errorf("error getting user repositories: %v", err)
		}

		if len(repos) == 0 {
			fmt.Printf("No repositories found for user: %s\n", config.user)
			return nil
		}

		fmt.Printf("Found %d repositories to scan\n", len(repos))
		for _, repoURL := range repos {
			// Extract repo name from clone URL
			repoName := strings.TrimSuffix(filepath.Base(repoURL), ".git")
			imageName := fmt.Sprintf("ghcr.io/%s/%s:latest", config.user, repoName)
			fmt.Printf("Processing image: %s\n", imageName)
			if err := processImage(imageName, config); err != nil {
				// Log error but continue with other repositories
				fmt.Printf("Error processing %s: %v\n", imageName, err)
			}
		}
		return nil
	}

	// Handle user list
	if config.userListFile != "" {
		content, err := ioutil.ReadFile(config.userListFile)
		if err != nil {
			return fmt.Errorf("error reading user list file: %v", err)
		}
		users := strings.Split(strings.TrimSpace(string(content)), "\n")
		
		for _, user := range users {
			fmt.Printf("\nScanning GitHub Container Registry for user: %s\n", user)
			repos, err := getUserRepos(user, config.token)
			if err != nil {
				fmt.Printf("Error getting repositories for user %s: %v\n", user, err)
				continue
			}

			for _, repoURL := range repos {
				repoName := strings.TrimSuffix(filepath.Base(repoURL), ".git")
				imageName := fmt.Sprintf("ghcr.io/%s/%s:latest", user, repoName)
				fmt.Printf("Processing image: %s\n", imageName)
				if err := processImage(imageName, config); err != nil {
					fmt.Printf("Error processing %s: %v\n", imageName, err)
				}
			}
		}
		return nil
	}

	return fmt.Errorf("either --github-org, --user, --repo, or --user-list must be specified")
}

func postmanMain(config *Config) error {
	// If workspace ID is provided, scan only that workspace
	if config.workspaceID != "" {
		workspace := PostmanWorkspace{
			ID: config.workspaceID,
			Name: "Specified Workspace", // We don't have the name, but that's OK
		}
		fmt.Printf("Scanning specific workspace ID: %s\n", config.workspaceID)
		return runTruffleHogPostman(config.token, []PostmanWorkspace{workspace}, config.verify)
	}

	// Otherwise, fetch and scan all workspaces
	fmt.Println("Fetching Postman workspaces...")
	workspaces, err := getPostmanWorkspaces(config.token, config.search)
	if err != nil {
		return fmt.Errorf("failed to fetch Postman workspaces: %v", err)
	}

	if len(workspaces) == 0 {
		fmt.Println("No Postman workspaces found.")
		return nil
	}

	fmt.Printf("Found %d workspaces.\n", len(workspaces))
	return runTruffleHogPostman(config.token, workspaces, config.verify)
}

func getPostmanWorkspaces(token string, searchQuery string) ([]PostmanWorkspace, error) {
	url := fmt.Sprintf("%s/workspaces", postmanAPIBaseURL)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("error creating request: %v", err)
	}

	req.Header.Set("X-Api-Key", token)
	
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error making request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API request failed with status: %d", resp.StatusCode)
	}

	var response PostmanWorkspacesResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("error decoding response: %v", err)
	}

	if searchQuery != "" {
		searchQuery = strings.ToLower(searchQuery)
		filtered := []PostmanWorkspace{}
		for _, ws := range response.Workspaces {
			if strings.Contains(strings.ToLower(ws.Name), searchQuery) {
				filtered = append(filtered, ws)
			}
		}
		return filtered, nil
	}

	return response.Workspaces, nil
}

func runTruffleHogPostman(token string, workspaces []PostmanWorkspace, verify bool) error {
	for _, workspace := range workspaces {
		fmt.Printf("Running TruffleHog on Postman workspace: %s (ID: %s)\n", workspace.Name, workspace.ID)

		args := []string{
			"postman",
			"--token", token,
			"--workspace", workspace.ID,
		}

		if !verify {
			args = append(args, "--no-verification")
		}

		cmd := exec.Command("trufflehog", args...)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr

		if err := cmd.Run(); err != nil {
			fmt.Printf("Failed to scan workspace %s: %v\n", workspace.Name, err)
		}
	}

	fmt.Println("TruffleHog scanning completed for all workspaces.")
	return nil
}

func dockerMain(config *Config) error {
	if config.scanOrg == "" {
		return fmt.Errorf("--scan-org is required for 'docker' command")
	}

	if config.token != "" {
		if err := dockerLogin("", "oauth2", config.token); err != nil {
			return err
		}
	}

	fmt.Printf("Fetching Docker Hub repositories for organization: %s\n", config.scanOrg)
	repositories, err := getDockerHubImages(config.scanOrg)
	if err != nil {
		return err
	}

	for _, repoName := range repositories {
		fmt.Printf("Processing repository: %s\n", repoName)
		tags, err := getDockerHubTags(config.scanOrg, repoName)
		if err != nil {
			fmt.Printf("Error fetching tags for %s: %v\n", repoName, err)
			continue
		}

		for _, tag := range tags {
			imageName := fmt.Sprintf("%s/%s:%s", config.scanOrg, repoName, tag)
			if err := processImage(imageName, config); err != nil {
				fmt.Printf("Error processing image %s: %v\n", imageName, err)
			}
		}
	}

	return nil
}

func processImage(imageName string, config *Config) error {
	// Pull the image
	if err := pullDockerImage(imageName, config.token, config.v1Convert); err != nil {
		// Clean up any directories that might have been created during failed pull
		if !config.retainImage {
			cleanupImageDirectories(imageName)
		}
		return err
	}

	// Extract layers if requested
	if config.extractLayers != "" {
		if err := extractDockerImageLayers(imageName, config.extractLayers); err != nil {
			// Clean up on failure if not retaining
			if !config.retainImage {
				cleanupImageDirectories(imageName)
				deleteDockerImage(imageName)
			}
			return err
		}
	} else {
		// Scan the image if not extracting layers
		if err := scanDockerImage(imageName, config.verify, config.v1Convert); err != nil {
			// Clean up on failure if not retaining
			if !config.retainImage {
				cleanupImageDirectories(imageName)
				deleteDockerImage(imageName)
			}
			return err
		}
	}

	// Clean up unless retain_image is passed
	if !config.retainImage {
		// Clean up directories first
		if err := cleanupImageDirectories(imageName); err != nil {
			fmt.Printf("Warning: Failed to clean up directories for %s: %v\n", imageName, err)
		}
		// Then delete the Docker image
		if err := deleteDockerImage(imageName); err != nil {
			return err
		}
	}

	return nil
}

func pullDockerImage(imageName string, token string, v1Convert bool) error {
	fmt.Printf("Pulling image: %s\n", imageName)
	cmd := exec.Command("docker", "pull", imageName)
	if err := cmd.Run(); err != nil {
		if v1Convert {
			fmt.Println("Pull failed. Attempting manual conversion using skopeo...")
			return convertSchema1ToSchema2(imageName)
		}
		return fmt.Errorf("failed to pull image %s: %v", imageName, err)
	}
	fmt.Printf("Image %s pulled successfully!\n", imageName)
	return nil
}

func convertSchema1ToSchema2(imageName string) error {
	ociImage := fmt.Sprintf("oci:%s:latest", strings.ReplaceAll(imageName, "/", "_"))
	dockerImage := fmt.Sprintf("docker-daemon:%s", imageName)

	fmt.Printf("Converting %s from Schema 1 to Schema 2 using skopeo...\n", imageName)

	// Pull the image to OCI format
	cmd := exec.Command("skopeo", "copy", fmt.Sprintf("docker://%s", imageName), ociImage)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("error during conversion of %s: %v", imageName, err)
	}

	// Load the OCI image into Docker
	fmt.Printf("Loading the converted image into Docker: %s\n", dockerImage)
	cmd = exec.Command("skopeo", "copy", ociImage, dockerImage)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("error loading converted image: %v", err)
	}

	fmt.Printf("Successfully converted %s to Schema 2 format.\n", imageName)
	return nil
}

func extractDockerImageLayers(imageName, outputDirectory string) error {
	// Implementation of layer extraction
	// This is a placeholder - implement the actual layer extraction logic here
	return fmt.Errorf("docker layer extraction not implemented")
}

func getDockerHubImages(orgName string) ([]string, error) {
	url := fmt.Sprintf("https://hub.docker.com/v2/repositories/%s/", orgName)
	repositories := []string{}
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // Skip SSL verification
		},
	}

	for url != "" {
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			return nil, fmt.Errorf("error creating request: %v", err)
		}

		resp, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("error making request: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("API request failed with status: %d", resp.StatusCode)
		}

		var response DockerHubResponse
		if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
			return nil, fmt.Errorf("error decoding response: %v", err)
		}

		for _, repo := range response.Results {
			repositories = append(repositories, repo.Name)
		}

		url = response.Next
	}

	fmt.Printf("Found %d repositories for Docker Hub organization %s.\n", len(repositories), orgName)
	return repositories, nil
}

func getDockerHubTags(orgName, repoName string) ([]string, error) {
	url := fmt.Sprintf("https://hub.docker.com/v2/repositories/%s/%s/tags/", orgName, repoName)
	tags := []string{}
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // Skip SSL verification as in Python version
		},
	}

	for url != "" {
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			return nil, fmt.Errorf("error creating request: %v", err)
		}

		resp, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("error making request: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("API request failed with status: %d", resp.StatusCode)
		}

		var response DockerHubTagResponse
		if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
			return nil, fmt.Errorf("error decoding response: %v", err)
		}

		for _, tag := range response.Results {
			tags = append(tags, tag.Name)
		}

		url = response.Next
	}

	fmt.Printf("Found %d tags for repository %s.\n", len(tags), repoName)
	return tags, nil
}

func cleanupImageDirectories(imageName string) error {
	// Convert image name to a safe directory name
	dirName := strings.ReplaceAll(imageName, "/", "_")
	dirName = strings.ReplaceAll(dirName, ":", "_")

	// Common paths where Docker and skopeo create directories
	dirsToClean := []string{
		dirName,                    // Base directory
		fmt.Sprintf("oci:%s", dirName), // OCI directory
		fmt.Sprintf("docker-daemon:%s", dirName), // Docker daemon directory
	}

	for _, dir := range dirsToClean {
		if _, err := os.Stat(dir); !os.IsNotExist(err) {
			fmt.Printf("Cleaning up directory: %s\n", dir)
			if err := os.RemoveAll(dir); err != nil {
				fmt.Printf("Warning: Failed to remove directory %s: %v\n", dir, err)
			}
		}
	}
	return nil
} 
