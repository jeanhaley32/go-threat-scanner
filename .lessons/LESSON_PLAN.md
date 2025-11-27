# Go Threat Scanner: Interview Prep Learning Project

## Overview

Rebuild the shell-based GitHub threat scanner in Go, using it as a vehicle to refresh Go fundamentals, learn practical concurrency patterns, and apply Code Complete design principles—all within a 2-week timeline.

**Reference Files (in `.lessons/reference/`):**
- `gh-threat-scanner.sh` - Original bash implementation (study this first!)
- `threat-patterns.conf.template` - Config file format specification

**Test Fixtures (in `.lessons/reference/fixtures/`):**
- `test-threat.conf` - Minimal working config for testing
- `sample-package-lock.json` - npm lock file with "malicious" packages
- `sample-yarn.lock` - yarn lock file with "malicious" packages
- `expected-findings.json` - What your scanner should find (for verification)

**Validation Scripts (run these to verify your work):**
- `validate-phase1.sh` - Tests CLI + config parsing
- `validate-phase2.sh` - Tests GitHub API client
- `validate-phase3.sh` - Tests lock file parsers + threat detection
- `validate-phase4b.sh` - Tests worker pool + race conditions
- `validate-phase5.sh` - Tests output formats + graceful shutdown
- `validate-all.sh` - Runs all validations in sequence

---

## How to Use This Lesson Plan

**To start a lesson session:**
1. Open terminal in `go-threat-scanner/`
2. Start Claude Code
3. Say: "Let's continue the Go lesson. Load .lessons/TUTOR_BOOTSTRAP.md"

---

## Project Structure

```
go-threat-scanner/
├── cmd/
│   └── scanner/
│       └── main.go           # Entry point
├── internal/
│   ├── config/
│   │   └── config.go         # Configuration loading
│   ├── scanner/
│   │   ├── scanner.go        # Core scanner orchestration (embeds github.Client)
│   │   ├── repository.go     # Single repo scanning
│   │   └── local.go          # Local directory scanning
│   ├── github/
│   │   └── client.go         # GitHub API client with rate limiting
│   ├── lockfile/
│   │   ├── npm.go            # package-lock.json parser (implement first)
│   │   ├── yarn.go           # yarn.lock parser (implement second)
│   │   ├── pnpm.go           # pnpm-lock.yaml parser
│   │   └── parser.go         # Interface extracted from implementations
│   ├── findings/
│   │   └── collector.go      # Thread-safe findings collection
│   └── output/
│       └── reporter.go       # Output formatting (JSON, text, quiet)
├── go.mod
├── go.sum
└── README.md
```

---

## Phase Plan (6 Phases)

### How Phases Build on Each Other

```
┌──────────────────────────────────────────────────────────────────┐
│                     FINAL PRODUCT: go-threat-scanner             │
│  ./scanner --config threat.conf --org mycompany --workers 4     │
└──────────────────────────────────────────────────────────────────┘
                                    ▲
                                    │
┌──────────────────────────────────────────────────────────────────┐
│ Phase 5: Polish                                                   │
│ Adds: Signal handling, proper rate limiting, output formats      │
│ Result: Production-ready scanner with Ctrl+C support             │
└──────────────────────────────────────────────────────────────────┘
                                    ▲
                                    │
┌──────────────────────────────────────────────────────────────────┐
│ Phase 4b: Worker Pool Scanner                                     │
│ Integrates: GitHub Client + Lock Parsers + Concurrency           │
│ Result: Concurrent scanner that works (but rough edges)          │
└──────────────────────────────────────────────────────────────────┘
                                    ▲
                    ┌───────────────┼───────────────┐
                    │               │               │
┌───────────────────┴───┐ ┌────────┴────────┐ ┌───┴───────────────┐
│ Phase 2: GitHub Client │ │ Phase 3: Parsers│ │ Phase 4a: Theory  │
│ Can: Fetch repos/files │ │ Can: Parse locks│ │ Can: Use channels │
└───────────────────────┘ └─────────────────┘ └───────────────────┘
                    ▲               ▲
                    └───────┬───────┘
                            │
            ┌───────────────┴───────────────┐
            │ Phase 1: CLI + Config          │
            │ Can: Parse args, load config   │
            └───────────────────────────────┘
                            ▲
                            │
            ┌───────────────┴───────────────┐
            │ Phase 0: Environment           │
            │ Can: Initialize Go project     │
            └───────────────────────────────┘
```

**Cumulative Deliverables:**

| After Phase | What You Can Run | What Works |
|-------------|------------------|------------|
| 0 | `go run ./cmd/scanner` | Prints "hello" and exits |
| 0.5 | (no code) | You understand the bash scanner architecture |
| 1 | `./scanner --config test-threat.conf --org acme` | Parses args, loads config, prints summary |
| 2 | `./scanner --test-api --org golang` | Fetches repos from GitHub, prints list |
| 3 | `./scanner --parse-file sample.lock --config test.conf` | Parses lock file, finds threats |
| 4a | (separate exercises) | Understands concurrency (not yet integrated) |
| 4b | `./scanner --config threat.conf --org acme --workers 4` | Scans repos concurrently, finds threats |
| 5 | `./scanner --config threat.conf --org acme --json` | Full scanner with graceful shutdown |

**Integration Points:**

- **Phase 2 → Phase 4b:** GitHub client becomes a field in Scanner struct
- **Phase 3 → Phase 4b:** Parsers called inside `scanRepo()` for each lock file found
- **Phase 4a → Phase 4b:** Theory directly applies to worker pool implementation

---

### Phase 0: Environment Setup (30 min)
**Goal:** Verify Go environment and understand module workflow

**Objectives - You're Done When:**
- [ ] `go version` shows 1.21+
- [ ] You can explain what `go.mod` and `go.sum` are for
- [ ] You've created the project directory with `go mod init`
- [ ] You can explain why Go doesn't have a `node_modules` folder

**You Do:**
1. Verify `go version` (1.21+ required)
2. Create project directory and initialize module
3. Understand `GOPATH` vs Go modules (modules won)

**Exercises Before Main Task:**

**Exercise 0.1: Environment Check**
```bash
# Run these and note the output:
go version
go env GOPATH
go env GOMODCACHE
```
Question: Where does Go store downloaded dependencies?

**Exercise 0.2: Module Initialization**
```bash
mkdir go-threat-scanner && cd go-threat-scanner
go mod init github.com/yourusername/go-threat-scanner
cat go.mod
```
Question: What's in go.mod right now? What will be added later?

**Exercise 0.3: Dependency Discovery**
```bash
# Create a simple main.go that imports "fmt" and prints "hello"
# Then run:
go mod tidy
cat go.mod
```
Question: Did go.mod change? Why or why not? (Hint: is `fmt` external?)

**Key Concepts:**
- Go modules replaced `GOPATH` workflow in Go 1.11+
- `go.mod` tracks dependencies; `go.sum` locks versions
- No `node_modules` equivalent—dependencies cached globally in `GOMODCACHE`

**Why This Matters:** Returning Go developers often hit module confusion. Get this right first to avoid "why won't this compile" frustration later.

---

### Phase 0.5: Bash Script Walkthrough (1 hour)
**Goal:** Understand what you're building before writing any Go

Before writing code, you need to understand the bash implementation you're porting. This prevents building blind.

**Study the Reference Script:**

Open `.lessons/reference/gh-threat-scanner.sh` and answer these questions:

**Exercise 0.5.1: Main Flow**
Find the main execution flow (search for "main" or look at the bottom of the script).
- What command-line arguments does it accept?
- What's the high-level sequence of operations?
- Where does output go?

**Exercise 0.5.2: Config Structure**
Read `.lessons/reference/threat-patterns.conf.template` completely.
- What fields are required vs optional?
- How are package lists formatted (space-separated? newline-separated?)
- What severity levels exist?

**Exercise 0.5.3: Core Functions**
Find and understand these bash functions:
- `load_threat_config()` - How does it parse the config file?
- `scan_repository()` - What does it check in each repo?
- `lock_has_package()` - How does it search lock files?
- `add_finding()` - What data structure holds findings?

**Exercise 0.5.4: Data Flow**
Trace how data flows through the scanner:
1. Config loaded → what variables are set?
2. Repos fetched → what API calls are made?
3. Lock files parsed → what patterns are matched?
4. Findings collected → how are they stored?
5. Output generated → what formats are supported?

**Deliverable:** You can explain the bash scanner's architecture in your own words.

**Acceptance Criteria:**
- Can list the 5 main phases of the scan process
- Can describe the config file format
- Can explain how findings are detected and stored
- Know which GitHub API endpoints are called

---

### Phase 1: Foundation & CLI (Days 1-2)
**Goal:** Working CLI that parses args and loads config

**Objectives - You're Done When:**
- [ ] Running `./scanner --help` shows usage information
- [ ] Running `./scanner --config threat.conf --org mycompany` parses args correctly
- [ ] Config file is loaded and validated (missing file = error, bad format = error)
- [ ] You can explain why config loading is in `internal/` not `cmd/`
- [ ] You can demonstrate how `defer` argument evaluation works

**You Build:**
- `cmd/scanner/main.go` - Entry point with flag parsing
- `internal/config/config.go` - Load threat config from file

**Config Parsing Requirements:**

The config file is bash-style `KEY=value` pairs. Your Go parser must handle:
```
THREAT_ENABLED=true                           # boolean
THREAT_NAME="Test Threat"                     # quoted string
THREAT_SEVERITY="CRITICAL"                    # enum: CRITICAL, WARNING, INFO
THREAT_PACKAGES="pkg1 pkg2 @scope/pkg3"      # space-separated list
THREAT_PACKAGE_VERSIONS="pkg@1.0.0 pkg2@2.0" # space-separated list
# Comments start with #
```

**Simplified Config Struct (start here):**
```go
type Config struct {
    Enabled         bool
    Name            string
    Severity        string
    Packages        []string  // Split on spaces
    PackageVersions []string  // Split on spaces
}
```

You'll expand this struct as you need more fields in later phases.

**Test with fixture:** Use `.lessons/reference/fixtures/test-threat.conf`

**Exercises Before Main Task:**

**Exercise 1.1: Package Organization**
Create this structure and verify imports work:
```
go-threat-scanner/
├── cmd/scanner/main.go      # package main, imports internal/greeter
├── internal/greeter/greet.go # package greeter, exports Greet()
```
Question: What happens if you try to import `internal/greeter` from outside this module?

**Exercise 1.2: Flag Parsing**
```go
// Write a program that accepts --name and --count flags
// Example: ./hello --name "World" --count 3
// Output: prints "Hello, World!" three times
```
Question: What's the zero value if the user doesn't provide `--count`?

**Exercise 1.3: Defer Timing**
```go
func main() {
    x := 1
    defer fmt.Println("deferred:", x)
    x = 2
    fmt.Println("current:", x)
}
```
Question: What prints first? What value does the deferred call print? Why?

**Exercise 1.4: Error Handling**
```go
// Write a function that opens a file and returns its first line
// Handle: file doesn't exist, file is empty, read error
// Use defer for cleanup
```
Question: If you `defer f.Close()` and then the read fails, does Close still run?

**Go Concepts Refreshed:**
- Package organization (`cmd/` vs `internal/`)
- `flag` package for CLI args
- Struct definitions and methods
- Error handling with `error` type
- File I/O with `os` and `bufio`
- **`defer` semantics** - resource cleanup guarantee

**Common Mistakes:**
- Forgetting that `defer` arguments are evaluated immediately, not at execution
- Using `log.Fatal` in library code (it calls `os.Exit`)
- Not checking errors from `Close()` calls

**Code Complete Principles:**
- **Single Responsibility:** Config loading separate from CLI
- **Defensive Programming:** Validate config before use
- **Fail Fast:** Exit early on invalid input

**Deliverable:** `./scanner --config threat.conf --org mycompany` parses and prints config

**Acceptance Criteria:**
```bash
# All of these should work:
./scanner --help                           # Shows usage
./scanner --config missing.conf            # Error: file not found
./scanner --config threat.conf --org acme  # Prints loaded config
./scanner --config threat.conf             # Error: --org required

# Test with the provided fixture:
./scanner --config .lessons/reference/fixtures/test-threat.conf --org test
# Should print:
#   Config loaded: "Test Threat (Learning Exercise)"
#   Severity: CRITICAL
#   Watching 3 packages, 2 package versions
#   Target org: test
```

**Verify Your Config Parser:**
```go
// Your config.Load() should produce:
cfg.Enabled == true
cfg.Name == "Test Threat (Learning Exercise)"
cfg.Packages == []string{"evil-package", "@malicious/crypto-stealer", "typosquat-lodash"}
cfg.PackageVersions == []string{"event-stream@3.3.6", "flatmap-stream@0.1.1"}
```

**Run Validation:**
```bash
./.lessons/reference/fixtures/validate-phase1.sh
```
All tests must pass before moving to Phase 2.

---

### Phase 2: GitHub API Client (Days 3-4)
**Goal:** HTTP client that fetches repos and files from GitHub

**Objectives - You're Done When:**
- [ ] `Client.GetRepos(org)` returns a slice of Repository structs
- [ ] `Client.GetFile(owner, repo, path)` fetches raw file content
- [ ] Errors include context (which org, which repo, which file failed)
- [ ] You can demonstrate error unwrapping with `errors.Is()`
- [ ] Rate limiting stub prevents hammering the API

**You Build:**
- `internal/github/client.go` - Wrap GitHub API calls

**Exercises Before Main Task:**

**Exercise 2.1: Basic HTTP GET**
```go
// Fetch https://api.github.com and print the response body
// Remember: what must you do with resp.Body?
```
Question: What happens if you forget `defer resp.Body.Close()`?

**Exercise 2.2: JSON Unmarshaling**
```go
// Define a struct to match this JSON:
// {"login": "octocat", "id": 1, "public_repos": 8}
// Fetch https://api.github.com/users/octocat and unmarshal it
```
Question: What happens if your struct field is named `Login` but the JSON key is `login`?

**Exercise 2.3: Error Wrapping**
```go
// Write a function that wraps errors with context:
func fetchUser(username string) (*User, error) {
    // If the HTTP call fails, the error should indicate which user failed
    // Use %w to allow unwrapping
}

// Test that this works:
err := fetchUser("nonexistent")
if errors.Is(err, someNetworkError) { ... }
```
Question: What's the difference between `%v` and `%w` in fmt.Errorf?

**Exercise 2.4: Status Code Handling**
```go
// Fetch https://api.github.com/users/this-user-does-not-exist-12345
// What's the status code? How do you handle non-200 responses?
```
Question: Does `http.Get` return an error for 404 responses?

**Go Concepts Refreshed:**
- `net/http` client
- JSON marshaling/unmarshaling with `encoding/json`
- Custom struct tags (`json:"field_name"`)
- **Error wrapping with `fmt.Errorf` and `%w`** (Go 1.13+ pattern)
- Basic rate limiting stub (`time.Sleep` between requests)

**Error Wrapping Pattern (Interview Topic):**
```go
resp, err := http.Get(url)
if err != nil {
    return nil, fmt.Errorf("fetching repos for org %s: %w", org, err)
}
// Later, callers can use errors.Is() and errors.As() to unwrap
```

**Common Mistakes:**
- Forgetting `defer resp.Body.Close()` (resource leak)
- Not checking `resp.StatusCode` (200 doesn't mean success for all APIs)
- Ignoring rate limit headers (X-RateLimit-Remaining)

**Code Complete Principles:**
- **Information Hiding:** API details behind clean interface
- **Abstraction:** `Client.GetRepos()` not `Client.MakeHTTPCall()`
- **Error Propagation:** Wrap errors with context using `%w`

**Rate Limiting Stub:**
Add `time.Sleep(100 * time.Millisecond)` between API calls now. This prevents hitting GitHub rate limits during development. We'll replace with proper `rate.Limiter` in Phase 5.

**Deliverable:** Fetch repo list and decode JSON into structs

**Intermediate CLI Command:**

Add a `--test-api` flag to verify your GitHub client works:

```bash
# Add this flag to main.go for Phase 2 testing:
./scanner --test-api --org golang

# Should output:
#   Fetching repos for org: golang
#   Found 42 repositories
#   - go (stars: 12345)
#   - vscode-go (stars: 6789)
#   - ...
```

This lets you verify Phase 2 works before Phase 3.

**Acceptance Criteria:**
```go
client := github.NewClient(os.Getenv("GH_TOKEN"))
repos, err := client.GetRepos("golang")
// Should return list of golang org repos
// Error should wrap underlying HTTP errors with context
```

```bash
# Verify with CLI:
export GH_TOKEN="your-token-here"
./scanner --test-api --org golang      # Works, lists repos
./scanner --test-api --org nonexistent # Error with context: "fetching repos for org nonexistent: 404 Not Found"
```

**Run Validation:**
```bash
export GH_TOKEN="your-token-here"  # Required for full validation
./.lessons/reference/fixtures/validate-phase2.sh
```
All tests must pass before moving to Phase 3.

---

### Phase 3: Lock File Parsing (Days 5-6)
**Goal:** Parse npm/yarn/pnpm lock files for package versions

**Objectives - You're Done When:**
- [ ] NpmParser parses package-lock.json and finds packages
- [ ] YarnParser parses yarn.lock and finds packages
- [ ] Both parsers implement the same interface (discovered, not designed upfront)
- [ ] You can explain the interface nil gotcha
- [ ] You can explain slice vs array semantics

**You Build (in this order):**
1. `internal/lockfile/npm.go` - package-lock.json parser (JSON) — implement first
2. `internal/lockfile/yarn.go` - yarn.lock parser (text) — implement second
3. `internal/lockfile/parser.go` - **Extract interface from what's common**

**Why This Order Matters:**
Go interfaces are *discovered*, not designed upfront. This is the opposite of Java. Build two concrete implementations first, then notice what they share. The interface emerges naturally and stays small.

**Exercises Before Main Task:**

**Exercise 3.1: Slice vs Array**
```go
func modifyArray(arr [3]int) { arr[0] = 999 }
func modifySlice(s []int) { s[0] = 999 }

func main() {
    arr := [3]int{1, 2, 3}
    modifyArray(arr)
    fmt.Println(arr[0])  // What prints?

    slice := []int{1, 2, 3}
    modifySlice(slice)
    fmt.Println(slice[0])  // What prints?
}
```
Question: Why are the results different?

**Exercise 3.2: Map Initialization**
```go
var m map[string]int
m["key"] = 1  // What happens?

m2 := make(map[string]int)
m2["key"] = 1  // What happens?
```
Question: What's the difference? Why does the first panic?

**Exercise 3.3: Interface Nil Gotcha**
```go
type Parser interface { Parse() }
type NpmParser struct{}
func (n *NpmParser) Parse() {}

func getParser(useNpm bool) Parser {
    var np *NpmParser
    if useNpm {
        np = &NpmParser{}
    }
    return np  // Returns interface containing (nil, *NpmParser) if !useNpm
}

func main() {
    p := getParser(false)
    fmt.Println(p == nil)  // What prints? Why?
}
```
Question: How would you fix `getParser` to return a proper nil interface?

**Exercise 3.4: Regex Compilation**
```go
// Version 1: Compile in function
func matchV1(s string) bool {
    re := regexp.MustCompile(`\d+`)
    return re.MatchString(s)
}

// Version 2: Compile at init
var digitRegex = regexp.MustCompile(`\d+`)
func matchV2(s string) bool {
    return digitRegex.MatchString(s)
}
```
Question: Why is V2 better for hot paths? What does `MustCompile` do if the regex is invalid?

**Go Concepts Refreshed:**
- **Slice vs array** - slices are references, arrays are values (interview topic)
- `encoding/json` for npm (struct tags, nested structures)
- `bufio.Scanner` for line-by-line parsing
- Regular expressions with `regexp` (compile once, reuse)
- Maps for O(1) package lookup
- **Interface nil gotcha** (see below)

**The Interface Nil Gotcha (Interview Topic):**
```go
var p *NpmParser = nil
var i LockfileParser = p
fmt.Println(i == nil)  // false! Interface holds (nil, *NpmParser)
```
An interface is only `nil` when both its type and value are nil.

**Common Mistakes:**
- Mutating a slice/map while iterating over it
- Assuming `regexp.MustCompile` is cheap (compile once at init)
- Creating interfaces with too many methods (Go prefers 1-2 method interfaces)

**Code Complete Principles:**
- **Encapsulation:** Each parser handles its own format
- **Table-Driven Design:** Package patterns as data, not code
- **Discovered Interfaces:** Let implementations drive interface design

**Deliverable:** `parser.HasPackage("lodash")` and `parser.GetVersion("lodash")` work for both formats

**Intermediate CLI Command:**

Add a `--parse-file` flag to test your parsers:

```bash
# Test npm parser with fixture:
./scanner --parse-file .lessons/reference/fixtures/sample-package-lock.json

# Should output:
#   Parsing: sample-package-lock.json (npm)
#   Found 5 packages:
#   - lodash@4.17.21
#   - express@4.18.2
#   - event-stream@3.3.6
#   - flatmap-stream@0.1.1
#   - evil-package@1.0.0

# Test yarn parser with fixture:
./scanner --parse-file .lessons/reference/fixtures/sample-yarn.lock

# Should output:
#   Parsing: sample-yarn.lock (yarn)
#   Found 6 packages:
#   - @malicious/crypto-stealer@1.0.0
#   - event-stream@3.3.6
#   - express@4.18.2
#   - flatmap-stream@0.1.1
#   - lodash@4.17.21
#   - typosquat-lodash@1.0.0
```

**Test Threat Detection (combine config + parser):**

```bash
# Now test that your parser + config find threats:
./scanner --parse-file .lessons/reference/fixtures/sample-package-lock.json \
          --config .lessons/reference/fixtures/test-threat.conf

# Should output:
#   CRITICAL: evil-package@1.0.0 - package in threat list
#   CRITICAL: event-stream@3.3.6 - version in threat list
#   CRITICAL: flatmap-stream@0.1.1 - version in threat list
#   Found 3 threats in sample-package-lock.json
```

Compare your output against `.lessons/reference/fixtures/expected-findings.json`

**Acceptance Criteria:**
```go
// Both should work identically:
npmParser := lockfile.NewNpmParser(npmContent)
yarnParser := lockfile.NewYarnParser(yarnContent)

// And both implement the same interface:
var p lockfile.Parser
p = npmParser
fmt.Println(p.HasPackage("lodash"))
fmt.Println(p.GetVersion("lodash"))
```

**Run Validation:**
```bash
./.lessons/reference/fixtures/validate-phase3.sh
```
All tests must pass before moving to Phase 4.

---

### Phase 4a: Goroutines & Channels Theory (Day 7)
**Goal:** Understand concurrency primitives before applying them

**Objectives - You're Done When:**
- [ ] You can draw the channel blocking rules table from memory
- [ ] You've created a data race and fixed it with a mutex
- [ ] You've created a deadlock and fixed it with proper channel usage
- [ ] You can explain what happens when you send on a closed channel
- [ ] You can read and interpret race detector output

**Before Writing Code:**
1. Understand what a data race is and why it's dangerous
2. Learn to read race detector output
3. Understand channel blocking semantics

**Exercises (All Required):**

**Exercise 4a.1: Create a Data Race**
```go
// Write a program with two goroutines incrementing the same counter
// Run with: go run -race main.go
// Observe the race detector output
```
Question: What two locations does the race detector show? What's the "previous write" and "read"?

**Exercise 4a.2: Fix the Race with Mutex**
```go
// Fix your race from 4a.1 using sync.Mutex
// Verify with: go run -race main.go (should show no races)
```
Question: What happens if you forget to Unlock()? How does defer help?

**Exercise 4a.3: Create a Deadlock**
```go
// Write a program that deadlocks with channels
// Example: two goroutines waiting for each other
```
Question: What does Go print when it detects a deadlock? (Hint: "fatal error: all goroutines are asleep")

**Exercise 4a.4: Channel Blocking Behavior**
```go
// Predict the output, then run:
func main() {
    ch := make(chan int)  // unbuffered
    ch <- 1               // What happens here?
    fmt.Println(<-ch)
}
```
Question: Why does this deadlock? How would you fix it?

**Exercise 4a.5: Buffered vs Unbuffered**
```go
// Predict the output:
func main() {
    ch := make(chan int, 2)  // buffered
    ch <- 1
    ch <- 2
    fmt.Println(<-ch)
    fmt.Println(<-ch)
}
```
Question: Why doesn't this deadlock like 4a.4?

**Exercise 4a.6: Channel Close Semantics**
```go
// Predict each output:
ch := make(chan int, 1)
ch <- 42
close(ch)
fmt.Println(<-ch)  // ?
fmt.Println(<-ch)  // ?
v, ok := <-ch      // v=? ok=?
```
Question: What happens if you send on a closed channel?

**Data Races Explained:**
```go
// This is a data race - undefined behavior
counter := 0
go func() { counter++ }()
go func() { counter++ }()
// counter could be 0, 1, or 2
```
Run with `go run -race` to detect. The race detector is your friend—use it always during development.

**Channel Blocking Rules (Memorize These):**
| Operation | Unbuffered | Buffered (not full) | Buffered (full) |
|-----------|------------|---------------------|-----------------|
| Send | Blocks until recv | Doesn't block | Blocks |
| Recv | Blocks until send | Doesn't block | Doesn't block |
| Close | Never blocks | Never blocks | Never blocks |

**Channel Close Semantics (Interview Topic):**
```go
ch := make(chan int)
close(ch)
v, ok := <-ch  // v=0, ok=false (channel closed)
<-ch           // returns zero value forever, never blocks
close(ch)      // PANIC: close of closed channel
```

**Deliverable:** Completed exercises with understanding of each concept

**Acceptance Criteria:**
- Can reproduce a race and fix it
- Can reproduce a deadlock and fix it
- Can write the blocking table without looking

---

### Phase 4 Integration Design (Required Reading Before 4b)

Before writing the worker pool, understand how the pieces fit together.

**The Big Picture:**

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           main.go                                       │
│  1. Parse flags (--config, --org, --workers)                           │
│  2. Load config via config.Load()                                      │
│  3. Create GitHub client                                               │
│  4. Create Scanner with client + config + worker count                 │
│  5. Call scanner.Run(ctx, org)                                         │
│  6. Output findings via reporter                                       │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                         scanner.Run(ctx, org)                           │
│                                                                         │
│  1. Fetch repo list: client.GetRepos(org) → []Repository               │
│  2. Start worker pool (N workers)                                      │
│  3. Send repos to jobs channel                                         │
│  4. Each worker calls scanRepo(repo) → []Finding                       │
│  5. Collect findings from results channel                              │
│  6. Return all findings                                                │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                      scanRepo(repo) → []Finding                         │
│                                                                         │
│  1. List files in repo: client.GetRepoContents(owner, repo, "/")       │
│  2. Find lock files: package-lock.json, yarn.lock, pnpm-lock.yaml      │
│  3. For each lock file found:                                          │
│     a. Fetch content: client.GetFileContent(owner, repo, path)         │
│     b. Detect format (npm/yarn/pnpm)                                   │
│     c. Parse with appropriate parser                                   │
│     d. Check each package against config.Packages                      │
│     e. Check each version against config.PackageVersions               │
│     f. Create Finding for each match                                   │
│  4. Return collected findings                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

**GitHub API Calls Needed (expand Phase 2 client):**

Your Phase 2 client needs these additional methods:
```go
// List contents of a directory in a repo
client.GetRepoContents(owner, repo, path string) ([]ContentItem, error)

// Fetch raw file content
client.GetFileContent(owner, repo, path string) ([]byte, error)
```

**API endpoints:**
- List contents: `GET /repos/{owner}/{repo}/contents/{path}`
- Get file: `GET /repos/{owner}/{repo}/contents/{path}` (returns base64 content)

**Data Structures:**

```go
type Repository struct {
    Name        string
    FullName    string  // "owner/repo"
    Description string
}

type Finding struct {
    Repository  string    // "owner/repo"
    File        string    // "package-lock.json"
    Package     string    // "evil-package"
    Version     string    // "1.0.0"
    Severity    string    // "CRITICAL"
    Reason      string    // "package in threat list"
}

type Scanner struct {
    client  *github.Client
    config  *config.Config
    workers int
}
```

**Key Integration Questions to Answer:**

1. Who owns the jobs channel? (Scanner creates it)
2. Who closes the jobs channel? (Job sender, after all repos sent)
3. Who closes the results channel? (Goroutine waiting on WaitGroup)
4. How does scanRepo get the config? (Scanner struct field)
5. How does scanRepo get the GitHub client? (Scanner struct field)

---

### Phase 4b: Worker Pool Implementation (Days 8-10)
**Goal:** Apply concurrency to the scanner

**Objectives - You're Done When:**
- [ ] Scanner runs multiple workers concurrently
- [ ] Jobs channel properly distributes work to workers
- [ ] Results channel collects findings from all workers
- [ ] Context cancellation stops all workers gracefully
- [ ] No race conditions (verified with `-race`)
- [ ] You can explain when to use errgroup vs manual WaitGroup

**You Build:**
- `internal/scanner/scanner.go` - Orchestrator with worker pool
- `internal/findings/collector.go` - Thread-safe findings buffer

**Exercises Before Main Task:**

**Exercise 4b.1: Simple Pipeline**
```go
// Build a pipeline: numbers -> double -> print
// Stage 1: generate numbers 1-5
// Stage 2: double each number
// Stage 3: print results
// Use unbuffered channels
```
Question: What happens if Stage 3 is slower than Stage 1?

**Exercise 4b.2: Fan-Out Pattern**
```go
// Send work to multiple workers
// Producer: sends 10 jobs to jobs channel
// Workers (3): each reads from jobs, processes, sends to results
// Collector: reads all results
```
Question: How do you know when all workers are done?

**Exercise 4b.3: Loop Variable Capture Bug**
```go
// Predict the output:
for i := 0; i < 3; i++ {
    go func() {
        fmt.Println(i)
    }()
}
time.Sleep(time.Second)
```
Question: Why doesn't this print 0, 1, 2? How do you fix it?

**Exercise 4b.4: Goroutine Leak**
```go
// This leaks a goroutine. Why? Fix it.
func process() <-chan int {
    ch := make(chan int)
    go func() {
        ch <- expensiveComputation()
    }()
    return ch
}

func main() {
    ch := process()
    // Never read from ch - what happens to the goroutine?
}
```
Question: What's the general rule for preventing goroutine leaks?

**Three Patterns to Learn (in order):**

**Pattern 1: Simple Pipeline (Unbuffered)**
```go
jobs := make(chan Repo)      // unbuffered
results := make(chan Finding) // unbuffered

go producer(jobs)            // sends repos
go worker(jobs, results)     // transforms
collector(results)           // receives findings
```
Start here. Understand blocking before adding buffers.

**Pattern 2: Buffered Work Queue**
```go
jobs := make(chan Repo, 100)  // buffer absorbs bursts
// Understand: what happens when buffer fills?
```

**Pattern 3: Worker Pool with Proper Shutdown**
```go
type Scanner struct {
    github  *github.Client  // struct embedding for method promotion
    workers int
    jobs    chan Repository
    results chan Finding
}

func (s *Scanner) Run(ctx context.Context, repos []Repository) ([]Finding, error) {
    var wg sync.WaitGroup

    // Start workers
    for i := 0; i < s.workers; i++ {
        wg.Add(1)
        go func() {
            defer wg.Done()
            for repo := range s.jobs {
                select {
                case <-ctx.Done():
                    return  // Stop on cancellation
                default:
                }
                findings := s.scanRepo(repo)
                for _, f := range findings {
                    select {
                    case s.results <- f:
                    case <-ctx.Done():
                        return
                    }
                }
            }
        }()
    }

    // Send jobs (in goroutine to avoid deadlock)
    go func() {
        for _, r := range repos {
            select {
            case s.jobs <- r:
            case <-ctx.Done():
                break
            }
        }
        close(s.jobs)  // Signal no more jobs
    }()

    // Wait for workers, then close results
    go func() {
        wg.Wait()
        close(s.results)
    }()

    // Collect results
    var findings []Finding
    for f := range s.results {
        findings = append(findings, f)
    }
    return findings, ctx.Err()
}
```

**Then: Introduce `errgroup` (Standard Library Solution)**
```go
import "golang.org/x/sync/errgroup"

g, ctx := errgroup.WithContext(ctx)
for _, repo := range repos {
    repo := repo  // capture loop variable
    g.Go(func() error {
        return s.scanRepo(ctx, repo)
    })
}
if err := g.Wait(); err != nil {
    return err
}
```
`errgroup` handles WaitGroup + first-error-wins + context cancellation. Learn the manual way first, then use this in production.

**Common Mistakes:**
- Goroutine leaks from unclosed channels
- Not capturing loop variables in goroutine closures
- Mixing buffered and unbuffered channels without understanding why
- Checking `ctx.Done()` only at the start, not during long operations

**Go Concepts (Core Focus):**
- **Goroutines:** Lightweight concurrency
- **Channels:** Communication between goroutines
- **sync.WaitGroup:** Coordination
- **sync.Mutex:** Protecting shared state (for findings collector)
- **context.Context:** Cancellation and timeouts
- **Struct embedding:** Scanner embeds github.Client

**Code Complete Principles:**
- **Minimize Scope:** Workers only see what they need
- **Coupling:** Loose coupling via channels
- **Cohesion:** Scanner owns its goroutines

**Deliverable:** Scan 10 repos concurrently with 4 workers, with proper cancellation support

**Acceptance Criteria:**
```bash
# Scanner completes without races:
go run -race ./cmd/scanner --config threat.conf --org golang --workers 4

# Ctrl+C during scan stops gracefully (not instant kill)
# Verify: "Shutting down..." message, clean exit
```

```go
// Code should demonstrate:
scanner := NewScanner(client, 4)  // 4 workers
ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
findings, err := scanner.Run(ctx, repos)
// Works with timeout and with manual cancel()
```

**Run Validation:**
```bash
export GH_TOKEN="your-token-here"  # Required for live API tests
./.lessons/reference/fixtures/validate-phase4b.sh
```
All tests must pass (especially race detection!) before moving to Phase 5.

---

### Phase 5: Graceful Shutdown & Polish (Days 11-14)
**Goal:** Production-ready error handling and clean shutdown

**Objectives - You're Done When:**
- [ ] Ctrl+C triggers graceful shutdown (current work completes)
- [ ] Second Ctrl+C forces immediate exit
- [ ] Rate limiter replaces the Phase 2 stub
- [ ] Output supports --json, --quiet, and default text modes
- [ ] You can explain when to use panic vs returning error
- [ ] Exit codes are correct (0 success, 1 error, 130 interrupted)

**You Build:**
- Signal handling (SIGINT/SIGTERM)
- Context cancellation propagation
- Rate limiting with `golang.org/x/time/rate` (replace the stub from Phase 2)
- `internal/output/reporter.go` - JSON/text/quiet modes

**Exercises Before Main Task:**

**Exercise 5.1: Signal Handling**
```go
// Write a program that:
// 1. Prints "Working..." every second
// 2. On Ctrl+C, prints "Shutting down..." and exits cleanly
// 3. On second Ctrl+C, prints "Force exit!" and exits immediately
```
Question: Why do we use a buffered channel (`make(chan os.Signal, 1)`) for signals?

**Exercise 5.2: Context Timeout**
```go
// Write a function that fetches a URL with a 5-second timeout
// If timeout expires, return an error
// Use context.WithTimeout
```
Question: What error type does ctx.Err() return on timeout vs cancellation?

**Exercise 5.3: Rate Limiter**
```go
// Create a rate limiter that allows 2 requests per second
// Make 10 requests and measure total time
// Should take ~5 seconds
```
Question: What's the difference between `limiter.Wait(ctx)` and `limiter.Allow()`?

**Exercise 5.4: Panic/Recover**
```go
// Write a function that recovers from panic and returns an error
func safeCall(f func()) (err error) {
    // Your implementation
}

// Test it:
err := safeCall(func() { panic("oops") })
fmt.Println(err)  // Should print error, not crash
```
Question: What happens if a goroutine panics and nobody recovers it?

**Go Concepts:**
- `os/signal` for interrupt handling
- Context cancellation chains
- `select` with multiple channels
- **panic/recover** (see below)

**panic/recover (Interview Topic):**
```go
// panic is for unrecoverable errors - use sparingly
func mustParse(s string) int {
    n, err := strconv.Atoi(s)
    if err != nil {
        panic(fmt.Sprintf("mustParse: %v", err))
    }
    return n
}

// recover only works in deferred functions
func safeCall(f func()) (err error) {
    defer func() {
        if r := recover(); r != nil {
            err = fmt.Errorf("panic recovered: %v", r)
        }
    }()
    f()
    return nil
}
```
**Rule:** Libraries should never panic. Only `main` packages can decide to panic. Use `recover` at API boundaries to convert panics to errors.

**Graceful Shutdown Pattern:**
```go
func main() {
    ctx, cancel := context.WithCancel(context.Background())

    // Handle signals
    sigChan := make(chan os.Signal, 1)
    signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

    go func() {
        sig := <-sigChan
        log.Printf("Received %v, shutting down gracefully...", sig)
        cancel()

        // Second signal = force exit
        <-sigChan
        log.Println("Force exit")
        os.Exit(1)
    }()

    scanner := NewScanner(cfg)
    if err := scanner.Run(ctx); err != nil {
        if errors.Is(err, context.Canceled) {
            log.Println("Scan interrupted")
            os.Exit(130)  // 128 + SIGINT(2)
        }
        log.Fatal(err)
    }
}
```

**Proper Rate Limiting:**
```go
import "golang.org/x/time/rate"

type Client struct {
    http    *http.Client
    limiter *rate.Limiter
}

func NewClient(token string) *Client {
    return &Client{
        http:    &http.Client{Timeout: 30 * time.Second},
        limiter: rate.NewLimiter(rate.Every(100*time.Millisecond), 1),
    }
}

func (c *Client) API(ctx context.Context, path string) (*http.Response, error) {
    if err := c.limiter.Wait(ctx); err != nil {
        return nil, err  // context cancelled
    }
    // ... make request
}
```

**Common Mistakes:**
- Not handling second SIGINT (user wants to force quit)
- Using `log.Fatal` in goroutines (doesn't run defers)
- Forgetting that `panic` across goroutine boundaries crashes the program

**Code Complete Principles:**
- **Defense in Depth:** Multiple layers catch errors
- **Clean Resources:** Always close channels, cancel contexts
- **Observable System:** Log state transitions

**Deliverable:** Full scanner with Ctrl+C handling, rate limiting, and multiple output formats

**Acceptance Criteria:**
```bash
# Default output (text):
./scanner --config threat.conf --org mycompany
# Human-readable findings

# JSON output:
./scanner --config threat.conf --org mycompany --json
# Machine-parseable JSON

# Quiet mode:
./scanner --config threat.conf --org mycompany --quiet
# Only findings, no progress

# Graceful shutdown:
./scanner --config threat.conf --org mycompany
# Press Ctrl+C -> "Shutting down gracefully..."
# Press Ctrl+C again -> "Force exit!" (immediate)

# Exit codes:
echo $?  # 0 = success, 1 = error, 130 = interrupted
```

**Run Validation:**
```bash
export GH_TOKEN="your-token-here"
./.lessons/reference/fixtures/validate-phase5.sh
```

**Run Full Validation Suite:**
```bash
./.lessons/reference/fixtures/validate-all.sh
```
All phases must pass before the final review.

---

## Key Interview Topics Covered

| Topic | Phase | Depth | Notes |
|-------|-------|-------|-------|
| Go modules & environment | 0 | ✓ | GOPATH vs modules confusion |
| Package organization | 1 | ✓✓ | `cmd/` vs `internal/` |
| defer semantics | 1 | ✓✓ | Argument evaluation timing |
| Error handling & wrapping | 1-5 | ✓✓✓ | `%w`, `errors.Is/As` |
| JSON marshaling | 2 | ✓✓ | Struct tags, nested structures |
| HTTP clients | 2 | ✓✓ | Response body handling |
| Slice vs array | 3 | ✓✓ | Reference vs value semantics |
| Interface nil gotcha | 3 | ✓✓ | Type + value both nil |
| Discovered interfaces | 3 | ✓✓ | Go's interface philosophy |
| Data races | 4a | ✓✓✓ | Race detector usage |
| Channel semantics | 4a | ✓✓✓ | Blocking rules, close behavior |
| Goroutines | 4b | ✓✓✓ | Lifecycle, leaks |
| Worker pools | 4b | ✓✓✓ | Three-pattern progression |
| errgroup | 4b | ✓✓ | stdlib concurrency helper |
| Struct embedding | 4b | ✓✓ | Method promotion |
| Context & cancellation | 4b,5 | ✓✓✓ | Propagation patterns |
| sync.Mutex/WaitGroup | 4b | ✓✓ | Protecting shared state |
| panic/recover | 5 | ✓✓ | When to use, library rules |
| Signal handling | 5 | ✓✓ | Graceful shutdown |
| Rate limiting | 2,5 | ✓✓ | Stub → proper limiter |

---

## Session Format

**Standard Phase (Phases 0-3, 5):**
1. **Concept Review** (10-15 min) - Quick refresher on Go concepts needed
2. **Design Discussion** (15 min) - Discuss approach, Code Complete principle
3. **You Code** (60-90 min) - Implement with hints as needed
4. **Review & Refine** (15 min) - Code review, idiomatic improvements
5. **Verify** (15 min) - Run with `-race`, test edge cases

**Concurrency Phase (Phase 4a & 4b) - Budget 2x Time:**
1. **Concept Deep Dive** (30 min) - Theory before code, memorize blocking rules
2. **Deliberate Bugs** (30 min) - Create and fix a race, create and fix a deadlock
3. **Design Discussion** (20 min) - Worker pool architecture
4. **You Code** (2-3 hours) - Concurrency bugs are subtle; don't rush
5. **Race Detector Session** (30 min) - Run `-race`, interpret output, fix issues
6. **Review & Refine** (30 min) - Review goroutine lifecycle, channel ownership

**Why the Time Difference:**
Concurrency bugs don't produce compiler errors. They produce "works on my machine" followed by production incidents. The extra time is for building intuition about program behavior you can't see.

---

## Success Criteria

By end of Phase 5, you should be able to:

1. **Explain** Go package organization, `internal/` convention, and module workflow
2. **Implement** proper error wrapping with `%w` and use `errors.Is/As`
3. **Design** interfaces by discovering them from implementations (not upfront)
4. **Recognize** the interface nil gotcha and slice/array semantic differences
5. **Draw** the channel blocking rules table from memory
6. **Implement** a worker pool from scratch with proper shutdown
7. **Debug** data races using the race detector
8. **Use** `errgroup` for common concurrent patterns
9. **Handle** graceful shutdown with context cancellation and signal handling
10. **Articulate** tradeoffs: buffered vs unbuffered, mutex vs channel, panic vs error

---

## Resource Links

**Official Documentation:**
- [Effective Go](https://go.dev/doc/effective_go) - The canonical style guide
- [Go Module Reference](https://go.dev/ref/mod) - Module system deep dive
- [Go Memory Model](https://go.dev/ref/mem) - Essential for understanding concurrency

**Phase-Specific Resources:**

| Phase | Resource | Why |
|-------|----------|-----|
| 0 | [Using Go Modules](https://go.dev/blog/using-go-modules) | Official tutorial on modules |
| 1 | [Organizing Go Code](https://go.dev/doc/code) | Project structure guidance |
| 2 | [net/http package](https://pkg.go.dev/net/http) | HTTP client reference |
| 2 | [Working with Errors in Go 1.13](https://go.dev/blog/go1.13-errors) | Error wrapping patterns |
| 3 | [Go Proverbs](https://go-proverbs.github.io/) | Interface philosophy explained |
| 4a | [Go Concurrency Patterns (video)](https://www.youtube.com/watch?v=f6kdp27TYZs) | Rob Pike's classic talk |
| 4a | [Share Memory By Communicating](https://go.dev/blog/codelab-share) | Core concurrency philosophy |
| 4b | [Concurrency is not Parallelism (video)](https://www.youtube.com/watch?v=oV9rvDllKEg) | Rob Pike on the distinction |
| 4b | [errgroup package](https://pkg.go.dev/golang.org/x/sync/errgroup) | stdlib concurrency helper |
| 5 | [Context package](https://pkg.go.dev/context) | Context deep dive |
| 5 | [rate package](https://pkg.go.dev/golang.org/x/time/rate) | Rate limiting reference |

**Books (Optional Deep Dives):**
- *Concurrency in Go* by Katherine Cox-Buday - Best Go concurrency book
- *The Go Programming Language* by Donovan & Kernighan - Comprehensive reference

---

## Reference Commands

```bash
# Initialize project
go mod init github.com/yourusername/go-threat-scanner

# Run scanner
go run ./cmd/scanner --config threat.conf --org mycompany

# Run with race detector (always do this during development)
go run -race ./cmd/scanner --config threat.conf --local ./testdir

# Build binary
go build -o scanner ./cmd/scanner
```

---

## Files from Shell Scanner to Reference

| Shell Function | Go Equivalent | Phase |
|---------------|---------------|-------|
| `load_threat_config()` | `config.Load()` | 1 |
| `gh_api()` | `github.Client.API()` | 2 |
| `lock_has_package()` | `lockfile.Parser.HasPackage()` | 3 |
| `scan_repository()` | `scanner.ScanRepo()` | 4b |
| `add_finding()` | `findings.Collector.Add()` | 4b |
| `generate_summary()` | `output.Reporter.Write()` | 5 |
