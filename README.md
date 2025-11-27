# Go Threat Scanner - Learning Project

A guided Go learning project that rebuilds a shell-based GitHub supply chain threat scanner in Go. Designed for intermediate developers refreshing Go skills, with focus on concurrency patterns and interview preparation.

## What You'll Build

A concurrent GitHub organization scanner that:
- Fetches repositories via GitHub API
- Parses npm/yarn lock files for dependencies
- Detects known malicious packages from a threat config
- Reports findings with multiple output formats
- Handles graceful shutdown on Ctrl+C

## What You'll Learn

| Phase | Topics |
|-------|--------|
| 0 | Go modules, environment setup |
| 0.5 | Understanding the reference bash implementation |
| 1 | CLI flags, config parsing, `defer` semantics |
| 2 | HTTP clients, JSON unmarshaling, error wrapping |
| 3 | Interface design, slice vs array, regex |
| 4a | Goroutines, channels, race detection |
| 4b | Worker pools, WaitGroup, context cancellation |
| 5 | Signal handling, rate limiting, graceful shutdown |

## Prerequisites

- Go 1.21+ installed
- GitHub account with personal access token
- Basic Go syntax knowledge (can be rusty)
- ~2 weeks of learning time

## Getting Started

1. **Clone this repo:**
   ```bash
   git clone https://github.com/jeanhaley/go-threat-scanner.git
   cd go-threat-scanner
   ```

2. **Start a lesson session:**
   ```bash
   # Open in your editor with Claude Code or similar AI assistant
   # Tell the AI: "Let's continue the Go lesson. Load .lessons/TUTOR_BOOTSTRAP.md"
   ```

3. **Follow the lesson plan:**
   - Read `.lessons/LESSON_PLAN.md` for the full curriculum
   - Work through phases sequentially
   - Run validation scripts after each phase

## Project Structure

```
go-threat-scanner/
├── .lessons/
│   ├── LESSON_PLAN.md           # Full curriculum (start here)
│   ├── TUTOR_BOOTSTRAP.md       # AI tutor persona and rules
│   ├── progress.yaml            # Track your progress
│   └── reference/
│       ├── gh-threat-scanner.sh # Original bash implementation
│       ├── threat-patterns.conf.template
│       └── fixtures/            # Test data and validation scripts
│           ├── test-threat.conf
│           ├── sample-package-lock.json
│           ├── sample-yarn.lock
│           ├── validate-phase1.sh
│           ├── validate-phase2.sh
│           ├── validate-phase3.sh
│           ├── validate-phase4b.sh
│           ├── validate-phase5.sh
│           └── validate-all.sh
├── cmd/scanner/                  # You build this
├── internal/                     # You build this
├── go.mod
└── README.md
```

## Validation

Each phase has automated validation:

```bash
# After completing Phase 1:
./.lessons/reference/fixtures/validate-phase1.sh

# Run all validations:
./.lessons/reference/fixtures/validate-all.sh
```

## Learning Approach

This project uses a **tutor-guided, hands-off** approach:
- The AI tutor presents objectives and teaches concepts
- **You** write all the code
- Validation scripts verify your implementation
- The tutor only shows solutions if explicitly asked

## Reference Implementation

The `.lessons/reference/` folder contains the original bash scanner you're porting. Study it in Phase 0.5 before writing Go code.

## License

MIT - Use this for learning, modify as needed.
