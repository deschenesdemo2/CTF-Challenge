*WORK IN PROGRESS ONLY CHALLENGE A MIGHT BE READY*

# VeraDemo.NET - Blab-a-Gag 🎯

> **⚠️ INTENTIONALLY VULNERABLE APPLICATION ⚠️**
> 
> This application contains deliberate security vulnerabilities for educational purposes. Do not deploy in production or report vulnerabilities - they're features, not bugs! 😉

## 🎪 Welcome to Blab-a-Gag

Blab-a-Gag is a quirky forum application where users share one-liner jokes, follow comedians, and heckle each other's content. But beneath its comedic surface lies a treasure trove of security challenges waiting to be discovered.

### Core Features
- **📝 Post Jokes**: Share your best one-liners with the community
- **👥 Follow System**: Listen to your favorite comedians or ignore the unfunny ones
- **💬 Heckling**: Comment and interact with other users' content
- **🛠️ Tools Page**: Utility functions for power users

## 🗺️ Application Map

| Endpoint | Description |
|----------|-------------|
| `/feed` | Your personalized joke feed |
| `/blabbers` | Discover and follow other users |
| `/profile` | Manage your comedian profile |
| `/login` | Authentication portal |
| `/register` | Join the comedy club |
| `/tools` | Utilities and system tools |

## 🚀 Quick Start

### Prerequisites
- Docker installed on your system

### Launch the Application
```bash
docker run -p 8080:8080 veracode/vulnerable-verademo-dotnet
```

Navigate to `http://127.0.0.1:8080` and start your comedy career!

## 🏁 Security Challenges

Ready to test your cybersecurity skills? This application contains five distinct challenges, each with its own flag to capture.

### Challenge A: SQL Injection Authentication Bypass
- **Target**: `/login` endpoint
- **Objective**: Bypass authentication using SQL injection techniques
- **Flag Location**: Successfully logging in reveals the flag as a joke post, in user profile, or via special endpoint

### Challenge B: Persistent Cross-Site Scripting (XSS)
- **Target**: Joke posting or comment system
- **Objective**: Inject malicious scripts that execute when other users view content
- **Flag Location**: Script execution reveals flag through DOM manipulation or redirection

### Challenge C: Command Injection
- **Target**: `/tools` page ping functionality
- **Objective**: Exploit command injection to execute system commands (e.g., `; cat flag.txt`)
- **Flag Location**: Command output displays the flag from file system or environment variables

### Challenge D: Insecure Direct Object Reference (IDOR)
- **Target**: User profiles and session management
- **Objective**: Access or modify another user's profile through ID manipulation
- **Flag Location**: Unauthorized profile access reveals the flag in user data or metadata

### Challenge E: Hidden Debug Endpoints
- **Target**: Undocumented debug or development endpoints
- **Objective**: Discover and access forgotten debug functionality
- **Flag Location**: Debug endpoint exposes sensitive information including the flag

## 📚 Documentation & Demos

- **[DEMO_NOTES.md](DEMO_NOTES.md)**: Comprehensive guide for Veracode scanning demonstrations
- **`docs/` folder**: In-depth vulnerability explanations and exploitation techniques

## 🔧 Development & CI Integration

### Local Development Build
```bash
docker pull mcr.microsoft.com/mssql/server:2017-CU24-ubuntu-16.04
docker build --no-cache -t verademo-dotnet .
docker run --rm -p 8080:8080 --name verademo verademo-dotnet
```

### CI/CD Integration
Pre-configured build files for popular CI systems:

| Platform | Configuration File |
|----------|-------------------|
| **GitHub Actions** | `.github/workflows/the-essentials.yml` |
| **Azure DevOps** | `azure-pipelines.yml` |
| **Jenkins** | `Jenkinsfile` |
| **GitLab** | `.gitlab-ci.yml` |
| **AWS CodeStar** | `AWS-CodeStar.md` |

### Required Secrets
Configure these environment variables in your CI system:
- `VERACODE_API_ID` & `VERACODE_API_KEY`: [Veracode API credentials](https://docs.veracode.com/r/c_api_credentials3)
- `SRCCLR_API_TOKEN`: [SCA agent token](https://docs.veracode.com/r/Integrate_Veracode_SCA_Agent_Based_Scanning_with_Your_CI_Projects)

## 🛠️ Technology Stack

- **Framework**: ASP.NET Core MVC (.NET Core 3.1)
- **Database**: SQL Server 2017 Express
- **Container**: Docker-based deployment

## 🎯 Learning Objectives

This application demonstrates real-world security vulnerabilities including:
- Authentication bypass techniques
- Cross-site scripting (XSS) attacks
- Command injection vulnerabilities
- Access control failures
- Information disclosure through debug endpoints

Perfect for security researchers, penetration testers, and developers learning secure coding practices.

---

**Happy Hacking! 🔓**

*Remember: This is a learning environment. Always practice responsible disclosure and ethical hacking principles in real-world scenarios.*
