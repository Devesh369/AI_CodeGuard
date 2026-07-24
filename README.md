# CodeGuard - AI Code Security Platform

CodeGuard is an AI-powered Python security and code analyzer platform that combines AST static scanning with Gemini AI to detect PEP-8 Pylint convention issues and Bandit security vulnerabilities.

---

## 🚀 Quick Start - Running Locally

### Prerequisites
- **Node.js**: v18 or v20+
- **Python** (Optional, for native CLI scanners): Python 3.8+ with `pylint` and `bandit`
  ```bash
  pip install pylint bandit
  ```

### Step 1: Environment Setup
1. Clone or export the project directory.
2. Copy `.env.example` to `.env`:
   ```bash
   cp .env.example .env
   ```
3. Set your **Gemini API Key** in `.env`:
   ```env
   GEMINI_API_KEY=your_gemini_api_key_here
   SESSION_SECRET=your_custom_secret_key
   ```

### Step 2: Install & Run
```bash
# Install dependencies
npm install

# Run development server with live reload
npm run dev
```

Open [http://localhost:3000](http://localhost:3000) in your browser.

---

## 🐳 Running Locally with Docker

You can run CodeGuard inside Docker with Node.js and pre-installed Python CLI tools:

```bash
# Build Docker image
docker build -t codeguard .

# Run container on port 3000
docker run -p 3000:3000 -e GEMINI_API_KEY=your_gemini_api_key_here codeguard
```

---

## ☁️ Deploying to AWS

### Option 1: AWS App Runner (Recommended - Easiest & Fastest)
AWS App Runner automatically builds and deploys containerized web applications.

1. **Push Container to Amazon ECR**:
   ```bash
   # Authenticate Docker to AWS ECR
   aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin <aws_account_id>.dkr.ecr.us-east-1.amazonaws.com

   # Create ECR repository
   aws ecr create-repository --repository-name codeguard

   # Tag and push image
   docker tag codeguard:latest <aws_account_id>.dkr.ecr.us-east-1.amazonaws.com/codeguard:latest
   docker push <aws_account_id>.dkr.ecr.us-east-1.amazonaws.com/codeguard:latest
   ```
2. **Deploy Service in AWS Console**:
   - Go to **AWS App Runner** -> **Create Service**.
   - Choose **Container registry** -> **Amazon ECR** and select the `codeguard` repository.
   - Under **Environment variables**, set `GEMINI_API_KEY` and `SESSION_SECRET`.
   - Set Port to `3000`.
   - Click **Create & Deploy**.

---

### Option 2: AWS Lightsail / EC2 Instance

1. **Launch Ubuntu 22.04 LTS EC2 / Lightsail instance** (Port 3000 open in Security Group).
2. **SSH into server & install Docker**:
   ```bash
   sudo apt update && sudo apt install -y docker.io git
   sudo systemctl enable --now docker
   ```
3. **Clone project & start container**:
   ```bash
   docker build -t codeguard .
   docker run -d -p 80:3000 --restart always -e GEMINI_API_KEY=your_key codeguard
   ```

---

## 🛠 Project Architecture
- `server.ts`: Express backend server hosting AI analysis endpoints, authentication, PDF export, and file management.
- `runStaticPythonScanner()`: Python AST static engine enforcing Pylint PEP-8 & Bandit security rule vectors.
- `analyzePythonFile()`: Gemini AI integration synthesizing static metrics into complete security patches and fixed code.
