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



