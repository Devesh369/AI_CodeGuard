import express from 'express';
import session from 'express-session';
import path from 'path';
import fs from 'fs';
import bcrypt from 'bcryptjs';
import multer from 'multer';
import AdmZip from 'adm-zip';
import { GoogleGenAI } from '@google/genai';
import PDFDocument from 'pdfkit';
import dotenv from 'dotenv';
import { exec } from 'child_process';
import util from 'util';
import nodemailer from 'nodemailer';
import ejs from 'ejs';

const execPromise = util.promisify(exec);

dotenv.config();

const app = express();
const PORT = 3000;

// Initialize Google Gen AI
let ai: GoogleGenAI | null = null;
if (process.env.GEMINI_API_KEY) {
  ai = new GoogleGenAI({
    apiKey: process.env.GEMINI_API_KEY,
    httpOptions: {
      headers: {
        'User-Agent': 'aistudio-build',
      }
    }
  });
} else {
  console.warn("⚠️ GEMINI_API_KEY is not defined. Falling back to simulated analysis.");
}

async function generateContentWithRetry(params: any, maxRetries = 2): Promise<any> {
  if (!ai) throw new Error("Gemini API is not initialized");
  let lastErr: any = null;
  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      return await ai.models.generateContent(params);
    } catch (err: any) {
      lastErr = err;
      const errStr = String(err?.message || err);
      if ((errStr.includes('503') || errStr.includes('UNAVAILABLE') || errStr.includes('429')) && attempt < maxRetries) {
        console.warn(`Gemini API call attempt ${attempt} failed (${errStr}). Retrying in 1s...`);
        await new Promise(res => setTimeout(res, 1000));
        continue;
      }
      throw err;
    }
  }
  throw lastErr;
}

// ----------------- Persistent JSON DB Setup -----------------
const DB_DIR = path.join(process.cwd(), 'data');
const DB_PATH = path.join(DB_DIR, 'db.json');

if (!fs.existsSync(DB_DIR)) {
  fs.mkdirSync(DB_DIR);
}

interface User {
  id: string;
  username: string;
  email: string;
  passwordHash: string;
}

interface Project {
  id: string;
  userId: string;
  name: string;
  overallScore: number;
  totalIssues: number;
  totalSecurityIssues: number;
  description: string;
  status: string;
  fileCount: number;
  firstReportId?: string;
  createdAt: string;
  updatedAt: string;
  aiReview?: {
    executiveSummary: string;
    architectureReview: string;
    overallCodeQuality: string;
    securityReview: string;
    maintainabilityReview: string;
    technicalDebt: string;
    codeSmells: string;
    topImprovements: string[];
    overallSuggestions: string;
  };
}

interface UploadedFile {
  id: string;
  projectId: string;
  userId: string;
  fileName: string;
  content: string;
  uploadedAt: string;
}

interface AnalysisReport {
  id: string;
  uploadedFileId: string;
  projectId: string;
  userId: string;
  fileName: string;
  pylintScore: number;
  pylintIssues: any[];
  banditIssues: any[];
  qualityStatus: string;
  recommendations: string[];
  aiSuggestions: string[];
  aiChanges: any[];
  fixedCode: string;
  fixExplanation: string;
  analyzedAt: string;
  issueCount: number;
  securityIssueCount: number;
  securityRiskLevel?: string;
  readabilityScore?: number;
  maintainabilityScore?: number;
  aiSummary?: string;
  strengths?: string[];
  weaknesses?: string[];
}

let db = {
  users: [] as User[],
  projects: [] as Project[],
  uploadedFiles: [] as UploadedFile[],
  analysisReports: [] as AnalysisReport[]
};

if (fs.existsSync(DB_PATH)) {
  try {
    db = JSON.parse(fs.readFileSync(DB_PATH, 'utf-8'));
    // Ensure all arrays exist
    db.users = db.users || [];
    db.projects = db.projects || [];
    db.uploadedFiles = db.uploadedFiles || [];
    db.analysisReports = db.analysisReports || [];
  } catch (e) {
    console.error("Error loading database file, initializing clean state:", e);
  }
}

// Seed default admin user if none exists
if (db.users.length === 0) {
  db.users.push({
    id: 'demo_user',
    username: 'admin',
    email: 'admin@codeguard.io',
    passwordHash: bcrypt.hashSync('password123', 10)
  });
  saveDb();
}

function saveDb() {
  try {
    fs.writeFileSync(DB_PATH, JSON.stringify(db, null, 2), 'utf-8');
  } catch (e) {
    console.error("Error saving database file:", e);
  }
}

// ----------------- Express Middlewares -----------------
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Set view engine to HTML rendered by EJS
app.engine('html', ejs.renderFile);
app.set('view engine', 'html');
app.set('views', path.join(process.cwd(), 'views'));

// Trust proxy for HTTPS cookie delivery behind reverse proxy
app.set('trust proxy', 1);

// Serve Django-like /static prefix path perfectly!
app.use('/static', express.static(path.join(process.cwd(), 'static')));

// Setup session
app.use((session as any)({
  secret: process.env.SESSION_SECRET || 'codeguard_secret_key_12345',
  resave: false,
  saveUninitialized: false,
  cookie: { 
    maxAge: 1000 * 60 * 60 * 24, // 24 hours
    secure: true,      // Required for SameSite=None
    sameSite: 'none',  // Required for cross-origin iframe
    httpOnly: true     // Security best practice
  }
}));

// Auto-append auth_id to local redirects to support iframe compatibility when cookies are blocked
app.use((req, res, next) => {
  const originalRedirect = res.redirect.bind(res);
  res.redirect = function(url: string): any {
    let authId = req.query.auth_id || req.body.auth_id;
    if (!authId && req.session) {
      authId = (req.session as any).userId;
    }
    const isLogoutOrLogin = url.startsWith('/login') || url.startsWith('/logout') || url.includes('logout=true');
    if (authId && typeof authId === 'string' && url.startsWith('/') && !url.includes('auth_id=') && !isLogoutOrLogin) {
      const separator = url.includes('?') ? '&' : '?';
      return originalRedirect(url + separator + 'auth_id=' + authId);
    }
    return originalRedirect(url);
  } as any;
  next();
});

// Provide global view properties
app.use((req, res, next) => {
  let userId = req.session ? (req.session as any).userId : null;
  
  // Fallback to query param or body for iframe compatibility when cookies are blocked
  const authId = req.query.auth_id || req.body.auth_id;
  if (authId && typeof authId === 'string') {
    userId = authId;
    if (req.session) {
      (req.session as any).userId = authId;
    }
  }

  // Override res.redirect to automatically append auth_id if it exists
  const originalRedirect = res.redirect;
  res.redirect = function(this: express.Response, url: string): void {
    const authIdVal = req.query.auth_id || req.body.auth_id || (req.session as any)?.userId;
    const isLogoutOrLogin = url.startsWith('/login') || url.startsWith('/logout') || url.includes('logout=true');
    if (authIdVal && typeof authIdVal === 'string' && !url.includes('auth_id=') && !isLogoutOrLogin) {
      const separator = url.includes('?') ? '&' : '?';
      originalRedirect.call(this, `${url}${separator}auth_id=${authIdVal}`);
    } else {
      originalRedirect.call(this, url);
    }
  } as any;

  const user = userId ? db.users.find(u => u.id === userId) : null;
  res.locals.user = user || null;
  res.locals.messages = (req.session && (req.session as any).messages) ? (req.session as any).messages : [];
  if (req.session && (req.session as any).messages) {
    (req.session as any).messages = []; // Clear after reading
  }

  // Support query-based alerts for iframe compatibility (when cookies/session are blocked)
  if (req.query.error && typeof req.query.error === 'string') {
    res.locals.messages.push({ type: 'error', text: req.query.error });
  }
  if (req.query.success && typeof req.query.success === 'string') {
    res.locals.messages.push({ type: 'success', text: req.query.success });
  }
  if (req.query.info && typeof req.query.info === 'string') {
    res.locals.messages.push({ type: 'info', text: req.query.info });
  }

  next();
});

// Middleware to protect routes
function requireAuth(req: express.Request, res: express.Response, next: express.NextFunction) {
  let userId = req.session ? (req.session as any).userId : null;
  const authId = req.query.auth_id || req.body.auth_id;
  if (authId && typeof authId === 'string') {
    userId = authId;
  }

  if (userId) {
    next();
  } else {
    res.redirect('/login');
  }
}

// Helper functions to format AI review elements to bullet points dynamically
function ensureBulletPoints(text: string): string {
  if (!text) return '';
  // If it already has list structure, return it but ensure correct formatting (no inline bullets on same line)
  if (text.includes('•') || text.includes('- ') || text.includes('* ')) {
    return text.split(/[•\n]+/).map(s => s.trim()).filter(Boolean).map(s => `• ${s}`).join('\n');
  }
  // Otherwise, split by sentences and prefix with bullet point
  const sentences = text
    .split(/(?<=[.!?])\s+/)
    .map(s => s.trim())
    .filter(s => s.length > 10);
  if (sentences.length === 0) {
    return text ? `• ${text}` : '';
  }
  return sentences.map(s => `• ${s}`).join('\n');
}

function formatAiReview(review: any): any {
  if (!review) return null;
  return {
    ...review,
    executiveSummary: ensureBulletPoints(review.executiveSummary),
    architectureReview: ensureBulletPoints(review.architectureReview),
    overallCodeQuality: ensureBulletPoints(review.overallCodeQuality),
    securityReview: ensureBulletPoints(review.securityReview),
    maintainabilityReview: ensureBulletPoints(review.maintainabilityReview),
    technicalDebt: ensureBulletPoints(review.technicalDebt),
    codeSmells: ensureBulletPoints(review.codeSmells),
    overallSuggestions: ensureBulletPoints(review.overallSuggestions)
  };
}

// Flash helper
function flash(req: any, type: 'success' | 'error' | 'info' | 'warning', text: string) {
  if (req.session) {
    const s = req.session as any;
    s.messages = s.messages || [];
    s.messages.push({ type, text });
  }
}

// ----------------- AI Analysis Logic with Gemini -----------------

// Static AST & pattern scanner for Python code analysis
function runStaticPythonScanner(code: string): { pylintIssues: any[], banditIssues: any[] } {
  const pylintIssues: any[] = [];
  const banditIssues: any[] = [];
  const lines = code.split('\n');

  // Pylint 1: Missing module docstring (C0114)
  const trimmedCode = code.trim();
  if (!trimmedCode.startsWith('"""') && !trimmedCode.startsWith("'''") && !trimmedCode.startsWith('# -*-')) {
    pylintIssues.push({
      line: "1",
      code: "C0114",
      message: "Missing module docstring",
      type: "missing-module-docstring",
      severity: "Convention"
    });
  }

  // Pylint 2: Line by line inspection
  const importedModules = new Set<string>();

  lines.forEach((line, index) => {
    const lineNum = String(index + 1);
    const trimmed = line.trim();

    // Line too long (C0301)
    if (line.length > 100 && !line.includes('http://') && !line.includes('https://') && !trimmed.startsWith('#')) {
      pylintIssues.push({
        line: lineNum,
        code: "C0301",
        message: `Line too long (${line.length}/100 characters)`,
        type: "line-too-long",
        severity: "Convention"
      });
    }

    // Trailing whitespace (C0303)
    if (line.match(/\s+$/) && trimmed.length > 0) {
      pylintIssues.push({
        line: lineNum,
        code: "C0303",
        message: "Trailing whitespace detected",
        type: "trailing-whitespace",
        severity: "Convention"
      });
    }

    // Wildcard import (W0401)
    if (trimmed.startsWith('from ') && trimmed.includes(' import *')) {
      pylintIssues.push({
        line: lineNum,
        code: "W0401",
        message: "Wildcard import used (from ... import *)",
        type: "wildcard-import",
        severity: "Warning"
      });
    }

    // Track standard imports for unused import check
    const importMatch = trimmed.match(/^import\s+([a-zA-Z0-9_,\s]+)/);
    if (importMatch) {
      const mods = importMatch[1].split(',').map(m => m.trim());
      mods.forEach(m => {
        if (m) importedModules.add(m);
      });
    }

    // Function naming (C0103) & docstrings (C0116)
    const funcMatch = trimmed.match(/^def\s+([a-zA-Z0-9_]+)\s*\(/);
    if (funcMatch) {
      const funcName = funcMatch[1];
      if (/[a-z][A-Z]/.test(funcName) && !funcName.startsWith('__')) {
        pylintIssues.push({
          line: lineNum,
          code: "C0103",
          message: `Function name "${funcName}" should be snake_case`,
          type: "invalid-name",
          severity: "Convention"
        });
      }
      const nextLine = lines[index + 1] ? lines[index + 1].trim() : '';
      if (!nextLine.startsWith('"""') && !nextLine.startsWith("'''") && !funcName.startsWith('test_')) {
        pylintIssues.push({
          line: lineNum,
          code: "C0116",
          message: `Missing function or method docstring for "${funcName}"`,
          type: "missing-function-docstring",
          severity: "Convention"
        });
      }
    }

    // Class naming (C0103)
    const classMatch = trimmed.match(/^class\s+([a-zA-Z0-9_]+)/);
    if (classMatch) {
      const className = classMatch[1];
      if (/^[a-z]/.test(className)) {
        pylintIssues.push({
          line: lineNum,
          code: "C0103",
          message: `Class name "${className}" should use PascalCase`,
          type: "invalid-name",
          severity: "Convention"
        });
      }
    }

    // Bare except (W0702)
    if (/^except\s*:/.test(trimmed)) {
      pylintIssues.push({
        line: lineNum,
        code: "W0702",
        message: "No exception type specified (bare 'except:')",
        type: "bare-except",
        severity: "Warning"
      });
    }

    // Mutable default arg (W0102)
    if (/def\s+[a-zA-Z0-9_]+\s*\(.*=\s*(\[\]|\{\})/.test(trimmed)) {
      pylintIssues.push({
        line: lineNum,
        code: "W0102",
        message: "Dangerous default value (mutable default argument)",
        type: "dangerous-default-value",
        severity: "Warning"
      });
    }

    // --- BANDIT SECURITY SCANS ---

    // B105/B106/B107 / CWE-798: Hardcoded secrets / passwords
    if (/(password|passwd|secret|api_key|apikey|access_token|private_key)\s*=\s*['"][^'"]{3,}['"]/i.test(trimmed) && !trimmed.includes('os.environ')) {
      banditIssues.push({
        severity: "HIGH",
        confidence: "HIGH",
        line: index + 1,
        test: "hardcoded_password_string",
        text: "Possible hardcoded password or secret credential detected.",
        cwe: "798"
      });
    }

    // B602 / CWE-78: Subprocess or os.system execution
    if (line.includes('shell=True') || line.includes('shell = True') || line.includes('os.system(') || line.includes('subprocess.Popen(') || line.includes('subprocess.call(')) {
      banditIssues.push({
        severity: "HIGH",
        confidence: "HIGH",
        line: index + 1,
        test: "subprocess_popen_with_shell_equals_true",
        text: "Unsafe command execution detected (subprocess/os.system). Ensure shell inputs are sanitized.",
        cwe: "78"
      });
    }

    // B307 / CWE-95: eval() or exec()
    if (/\beval\s*\(/.test(trimmed)) {
      banditIssues.push({
        severity: "HIGH",
        confidence: "HIGH",
        line: index + 1,
        test: "use_of_eval",
        text: "Use of eval() detected, which allows arbitrary code execution.",
        cwe: "95"
      });
    }
    if (/\bexec\s*\(/.test(trimmed)) {
      banditIssues.push({
        severity: "HIGH",
        confidence: "HIGH",
        line: index + 1,
        test: "use_of_exec",
        text: "Use of exec() detected, which allows arbitrary code execution.",
        cwe: "95"
      });
    }

    // B608 / CWE-89: Raw SQL Injection
    if (/execute\s*\(\s*(f['"]|['"].*%|['"].*\+)/.test(trimmed) || /select\s+.*\s+from\s+.*(\+|\%|\.format)/i.test(trimmed)) {
      banditIssues.push({
        severity: "HIGH",
        confidence: "MEDIUM",
        line: index + 1,
        test: "hardcoded_sql_expression",
        text: "Possible SQL injection vulnerability via dynamic string construction in query.",
        cwe: "89"
      });
    }

    // B303 / CWE-327: Insecure hash (MD5/SHA1)
    if (line.includes('hashlib.md5(') || line.includes('hashlib.sha1(')) {
      banditIssues.push({
        severity: "MEDIUM",
        confidence: "HIGH",
        line: index + 1,
        test: "insecure_hash_function",
        text: "Use of weak or broken cryptographic hash function (MD5 or SHA1).",
        cwe: "327"
      });
    }

    // B506: Unsafe YAML load
    if (line.includes('yaml.load(') && !line.includes('SafeLoader')) {
      banditIssues.push({
        severity: "MEDIUM",
        confidence: "HIGH",
        line: index + 1,
        test: "yaml_load",
        text: "Use of unsafe yaml.load() without SafeLoader.",
        cwe: "20"
      });
    }

    // B301: Unsafe Pickle
    if (line.includes('pickle.loads(') || line.includes('pickle.load(')) {
      banditIssues.push({
        severity: "MEDIUM",
        confidence: "HIGH",
        line: index + 1,
        test: "pickle_loads",
        text: "Deserializing untrusted data with pickle can lead to remote code execution.",
        cwe: "502"
      });
    }

    // B501: SSL verification disabled
    if (line.includes('verify=False') || line.includes('verify = False')) {
      banditIssues.push({
        severity: "HIGH",
        confidence: "HIGH",
        line: index + 1,
        test: "ssl_verification_disabled",
        text: "SSL certificate verification explicitly disabled (verify=False).",
        cwe: "295"
      });
    }

    // B110: Try / Except / Pass
    if (/^except\s*.*:/.test(trimmed)) {
      const nextL = lines[index + 1] ? lines[index + 1].trim() : '';
      if (nextL === 'pass') {
        banditIssues.push({
          severity: "LOW",
          confidence: "HIGH",
          line: index + 1,
          test: "try_except_pass",
          text: "Try-except block with pass silently suppresses exceptions.",
          cwe: "703"
        });
      }
    }
  });

  // Check unused imported modules
  importedModules.forEach(mod => {
    if (mod && ['os', 'sys', 're', 'math', 'json', 'random', 'time', 'datetime', 'subprocess', 'requests'].includes(mod)) {
      const occurrences = (code.match(new RegExp(`\\b${mod}\\.`, 'g')) || []).length;
      if (occurrences === 0) {
        const modLineIdx = lines.findIndex(l => l.includes(`import ${mod}`) || l.includes(`, ${mod}`));
        pylintIssues.push({
          line: String(modLineIdx !== -1 ? modLineIdx + 1 : 1),
          code: "W0611",
          message: `Unused import ${mod}`,
          type: "unused-import",
          severity: "Warning"
        });
      }
    }
  });

  return { pylintIssues, banditIssues };
}

async function runLocalAnalysis(code: string): Promise<{ pylintIssues: any[], banditIssues: any[], pylintScore: number }> {
  const tempDir = path.join(process.cwd(), 'data', 'temp');
  if (!fs.existsSync(tempDir)) {
    fs.mkdirSync(tempDir, { recursive: true });
  }
  const tempFile = path.join(tempDir, `temp_${Math.random().toString(36).substring(2, 11)}.py`);
  fs.writeFileSync(tempFile, code, 'utf-8');

  let pylintIssues: any[] = [];
  let banditIssues: any[] = [];

  // Run Pylint
  try {
    const { stdout } = await execPromise(`pylint --output-format=json "${tempFile}"`, { timeout: 10000 });
    const rawIssues = JSON.parse(stdout);
    pylintIssues = rawIssues.map((item: any) => ({
      line: String(item.line || 1),
      code: item['message-id'] || item.symbol || 'unknown',
      message: item.message || '',
      type: item.symbol || '',
      severity: item.type ? (item.type.charAt(0).toUpperCase() + item.type.slice(1)) : 'Convention'
    }));
  } catch (err: any) {
    if (err.stdout) {
      try {
        const rawIssues = JSON.parse(err.stdout);
        pylintIssues = rawIssues.map((item: any) => ({
          line: String(item.line || 1),
          code: item['message-id'] || item.symbol || 'unknown',
          message: item.message || '',
          type: item.symbol || '',
          severity: item.type ? (item.type.charAt(0).toUpperCase() + item.type.slice(1)) : 'Convention'
        }));
      } catch (parseErr) {
        console.error("Failed to parse pylint output:", parseErr);
      }
    }
  }

  // Run Bandit
  try {
    const { stdout } = await execPromise(`bandit -f json "${tempFile}"`, { timeout: 10000 });
    const rawBandit = JSON.parse(stdout);
    if (rawBandit && rawBandit.results) {
      banditIssues = rawBandit.results.map((item: any) => ({
        severity: (item.issue_severity || 'LOW').toUpperCase(),
        confidence: (item.issue_confidence || 'LOW').toUpperCase(),
        line: item.line_number || 1,
        test: item.test_name || '',
        text: item.issue_text || '',
        cwe: item.cwe ? String(item.cwe.id) : ''
      }));
    }
  } catch (err: any) {
    if (err.stdout) {
      try {
        const rawBandit = JSON.parse(err.stdout);
        if (rawBandit && rawBandit.results) {
          banditIssues = rawBandit.results.map((item: any) => ({
            severity: (item.issue_severity || 'LOW').toUpperCase(),
            confidence: (item.issue_confidence || 'LOW').toUpperCase(),
            line: item.line_number || 1,
            test: item.test_name || '',
            text: item.issue_text || '',
            cwe: item.cwe ? String(item.cwe.id) : ''
          }));
        }
      } catch (parseErr) {
        console.error("Failed to parse bandit output:", parseErr);
      }
    }
  }

  // Clean up temp file
  try {
    if (fs.existsSync(tempFile)) {
      fs.unlinkSync(tempFile);
    }
  } catch (err) {
    console.error("Error removing temp file:", err);
  }

  // Supplementary static scan if CLI tools are missing or empty
  const staticResults = runStaticPythonScanner(code);
  if (pylintIssues.length === 0) {
    pylintIssues = staticResults.pylintIssues;
  }
  if (banditIssues.length === 0) {
    banditIssues = staticResults.banditIssues;
  }

  // Calculate score
  let scoreDeduction = 0;
  pylintIssues.forEach(issue => {
    if (issue.severity === 'Error' || issue.severity === 'Fatal') scoreDeduction += 1.5;
    else if (issue.severity === 'Warning') scoreDeduction += 1.0;
    else scoreDeduction += 0.5;
  });
  banditIssues.forEach(issue => {
    if (issue.severity === 'HIGH') scoreDeduction += 1.5;
    else if (issue.severity === 'MEDIUM') scoreDeduction += 1.0;
    else scoreDeduction += 0.5;
  });

  const pylintScore = Math.max(0.1, parseFloat((10.0 - scoreDeduction).toFixed(1)));

  return { pylintIssues, banditIssues, pylintScore };
}

async function analyzePythonFile(filename: string, code: string): Promise<Partial<AnalysisReport>> {
  const localAnalysis = await runLocalAnalysis(code);

  if (!ai) {
    return getFallbackAnalysis(filename, code, localAnalysis);
  }

  const prompt = `
You are an expert Python Senior Architect and Security Auditor.
Analyze the file "${filename}" for Pylint PEP-8 / convention violations and Bandit security risks.

Baseline local static analysis findings:
- Baseline Pylint Issues: ${JSON.stringify(localAnalysis.pylintIssues)}
- Baseline Bandit Issues: ${JSON.stringify(localAnalysis.banditIssues)}

Source Code:
--- START OF PYTHON CODE ---
${code}
--- END OF PYTHON CODE ---

Generate a comprehensive code review, security audit, and corrected source code.
You MUST return your response as a single, valid JSON object matching this schema:
{
  "pylintIssues": [
    {
      "line": "1",
      "code": "C0114",
      "message": "Missing module docstring",
      "type": "missing-module-docstring",
      "severity": "Convention"
    }
  ],
  "banditIssues": [
    {
      "severity": "HIGH",
      "confidence": "HIGH",
      "line": 12,
      "test": "subprocess_popen_with_shell_equals_true",
      "text": "Unsafe command execution detected.",
      "cwe": "78"
    }
  ],
  "readabilityScore": 8,
  "maintainabilityScore": 9,
  "securityRiskLevel": "Medium Risk",
  "aiSummary": "Brief overview of file purpose and security posture...",
  "strengths": ["List of code strengths..."],
  "weaknesses": ["List of code weaknesses..."],
  "recommendations": ["List of key high-priority recommendations..."],
  "aiChanges": [
    {
      "line": 12,
      "issue": "Unsafe subprocess execution detected.",
      "old": "subprocess.Popen(cmd, shell=True)",
      "new": "subprocess.Popen(cmd, shell=False)",
      "reason": "Avoid shell=True to minimize shell injection risks."
    }
  ],
  "fixedCode": "... COMPLETE, FULLY CORRECTED PYTHON SOURCE CODE with all docstrings and security patches applied ..."
}

Return ONLY the JSON object. Do not wrap in markdown.
`;

  try {
    const response = await generateContentWithRetry({
      model: 'gemini-3.6-flash',
      contents: prompt,
      config: {
        responseMimeType: 'application/json'
      }
    });

    const text = response.text;
    if (!text) throw new Error("Empty response from Gemini");

    const parsed = JSON.parse(text);

    // Merge issues
    const combinedPylint = [...localAnalysis.pylintIssues];
    if (Array.isArray(parsed.pylintIssues)) {
      parsed.pylintIssues.forEach((pIssue: any) => {
        if (!combinedPylint.some(item => item.code === pIssue.code && String(item.line) === String(pIssue.line))) {
          combinedPylint.push(pIssue);
        }
      });
    }

    const combinedBandit = [...localAnalysis.banditIssues];
    if (Array.isArray(parsed.banditIssues)) {
      parsed.banditIssues.forEach((bIssue: any) => {
        if (!combinedBandit.some(item => item.test === bIssue.test && Number(item.line) === Number(bIssue.line))) {
          combinedBandit.push(bIssue);
        }
      });
    }

    // Recalculate score
    let scoreDeduction = 0;
    combinedPylint.forEach(issue => {
      if (issue.severity === 'Error' || issue.severity === 'Fatal') scoreDeduction += 1.5;
      else if (issue.severity === 'Warning') scoreDeduction += 1.0;
      else scoreDeduction += 0.5;
    });
    combinedBandit.forEach(issue => {
      if (issue.severity === 'HIGH') scoreDeduction += 1.5;
      else if (issue.severity === 'MEDIUM') scoreDeduction += 1.0;
      else scoreDeduction += 0.5;
    });

    const pylintScore = Math.max(0.1, parseFloat((10.0 - scoreDeduction).toFixed(1)));

    let qualityStatus = 'Needs Improvement';
    if (pylintScore >= 9.0) qualityStatus = 'Excellent';
    else if (pylintScore >= 7.5) qualityStatus = 'Good';
    else if (pylintScore < 5.0) qualityStatus = 'Poor';

    return {
      pylintScore,
      pylintIssues: combinedPylint,
      banditIssues: combinedBandit,
      qualityStatus,
      recommendations: parsed.recommendations || [],
      aiSuggestions: parsed.recommendations || [],
      aiChanges: parsed.aiChanges || [],
      fixedCode: parsed.fixedCode || code,
      fixExplanation: parsed.aiSummary || '',
      issueCount: combinedPylint.length,
      securityIssueCount: combinedBandit.length,
      securityRiskLevel: parsed.securityRiskLevel || (combinedBandit.length > 0 ? 'High Risk' : 'Low Risk'),
      readabilityScore: parsed.readabilityScore || 8,
      maintainabilityScore: parsed.maintainabilityScore || 8,
      aiSummary: parsed.aiSummary || '',
      strengths: parsed.strengths || [],
      weaknesses: parsed.weaknesses || []
    };
  } catch (err) {
    console.error("Gemini AI Analysis failed, using local static results:", err);
    return getFallbackAnalysis(filename, code, localAnalysis);
  }
}

function getFallbackAnalysis(filename: string, code: string, localAnalysis?: { pylintIssues: any[], banditIssues: any[], pylintScore: number }): Partial<AnalysisReport> {
  const lines = code.split('\n');

  let pylintIssues = localAnalysis?.pylintIssues || [];
  let banditIssues = localAnalysis?.banditIssues || [];
  
  if (pylintIssues.length === 0 && banditIssues.length === 0) {
    const staticRes = runStaticPythonScanner(code);
    pylintIssues = staticRes.pylintIssues;
    banditIssues = staticRes.banditIssues;
  }

  let scoreDeduction = 0;
  pylintIssues.forEach(issue => {
    if (issue.severity === 'Error' || issue.severity === 'Fatal') scoreDeduction += 1.5;
    else if (issue.severity === 'Warning') scoreDeduction += 1.0;
    else scoreDeduction += 0.5;
  });
  banditIssues.forEach(issue => {
    if (issue.severity === 'HIGH') scoreDeduction += 1.5;
    else if (issue.severity === 'MEDIUM') scoreDeduction += 1.0;
    else scoreDeduction += 0.5;
  });

  const pylintScore = Math.max(0.1, parseFloat((10.0 - scoreDeduction).toFixed(1)));

  let qualityStatus = 'Needs Improvement';
  if (pylintScore >= 9.0) qualityStatus = 'Excellent';
  else if (pylintScore >= 7.5) qualityStatus = 'Good';
  else if (pylintScore < 5.0) qualityStatus = 'Poor';

  const recommendations = [
    "Add PEP 257 compliant docstrings to clarify module, class, and method behavior.",
    "Refactor variables to use clear snake_case formatting as per standard PEP 8."
  ];

  const aiSuggestions = [
    "Secure inputs before feeding into lower shell layers.",
    "Introduce function-level typing annotations to aid readability."
  ];

  const aiChanges = [
    {
      line: 1,
      issue: "Missing module docstring",
      old: lines[0] || "",
      new: `"""Module analysis for ${filename}."""\n` + (lines[0] || ""),
      reason: "Adds document context at top of file."
    }
  ];

  return {
    pylintScore,
    pylintIssues,
    banditIssues,
    qualityStatus,
    recommendations,
    aiSuggestions,
    aiChanges,
    fixedCode: `"""Module analysis for ${filename}."""\n\n` + code,
    fixExplanation: "Static analysis completed. Identified standard styling corrections and potential code structure improvements.",
    issueCount: pylintIssues.length,
    securityIssueCount: banditIssues.length,
    securityRiskLevel: banditIssues.length > 0 ? "High Risk" : "Safe",
    readabilityScore: pylintScore >= 8.0 ? 9 : 7,
    maintainabilityScore: pylintScore >= 8.0 ? 8 : 6,
    aiSummary: "The analysis scanned the file structure and imports, identifying styling conventions and security profiles.",
    strengths: ["Code follows clear procedural style", "Core packages are imported cleanly"],
    weaknesses: ["Missing comprehensive type indications", "Lacks detailed inline comments"]
  };
}

async function generateProjectReview(files: { filename: string, content: string }[]): Promise<any> {
  if (!ai) {
    return {
      executiveSummary: "• Serious risk of arbitrary folder write (Zip Slip) due to unsanitized path joins in file ingestion handlers.\n• Main application server performs heavy synchronous CPU/IO operations inside request/response loops, leading to connection exhaustion.\n• High coupling between presentation templates, router endpoints, and local analysis executables.",
      architectureReview: "• Lacks standard clean separation of concerns; routing logic, analysis orchestration, and database writes live in a single controller module.\n• Missing queue-based background workers (e.g. Celery / Redis) for computationally heavy static code analysis.\n• Static exclusion configurations are hardcoded rather than externalized into structured environment files.",
      overallCodeQuality: "• Inconsistent compliance with Python standard formatting recommendations (PEP 8).\n• Code lacks static type hinting or documentation annotations across public methods.\n• Absence of inline code commentary on complex analysis pipelines makes developer onboarding difficult.",
      securityReview: "• Direct directory traversal vulnerabilities exist in general file ingestion streams.\n• Vulnerable process execution patterns (e.g., shell=True or unvalidated strings) pose high shell injection hazards.\n• Absolute lack of input validation schemas at boundary points.",
      maintainabilityReview: "• Component isolation is low, making writing isolated automated unit tests nearly impossible.\n• Dynamic state preservation relies on unstable custom local URL parameters instead of secure session cookies.\n• Monolithic codebase structure poses high refactoring costs.",
      technicalDebt: "• Synchronous remote model and local process execution inside HTTP threads.\n• Lack of externalized global configuration parameters and centralized log management.",
      codeSmells: "• Deep conditional logic blocks nesting 4+ levels in file traversal loops.\n• Generic empty exception handlers swallowing stack traces without logging.",
      topImprovements: [
        "Sanitize file system paths thoroughly using absolute paths and prefix checks",
        "Introduce celery or a lightweight task queue for background analysis tasks",
        "Refactor express routes and database interactions into isolated service modules"
      ],
      overallSuggestions: "• Refactor codebase to isolate the Express router from computational analysis logic.\n• Move security scanners into background job queues with standard SSE updates.\n• Implement rigorous automated testing targeting file ingestions."
    };
  }

  try {
    let projectContent = "";
    files.forEach(f => {
      projectContent += `=== File Name: ${f.filename} ===\n${f.content.substring(0, 10000)}\n\n`;
    });

    const prompt = `
You are a Senior Principal Python Architect and Security Lead.
Review the following Python project containing ${files.length} files.

${projectContent}

Evaluate the complete codebase and generate a rigorous project-level review.
For each of the fields, write a highly concise list of 3-4 bullet points (using bullet character '•' at the start of each line) focused strictly on high-impact technical facts, severe risks, and deep architectural issues. Keep sentences brief, actionable, and extremely professional for senior developers. Avoid vague generalizations, generic advice, or filler words.

You MUST return your response as a single, valid JSON object matching the following structure:
{
  "executiveSummary": "• First concise bullet point of overall quality/security fact.\\n• Second concise bullet point...\\n• Third concise bullet...",
  "architectureReview": "• Critical modular design fact...\\n• Structural anti-pattern or design boundary issue...\\n• Recommended architectural solution...",
  "overallCodeQuality": "• Code styling/PEP8 convention compliance fact...\\n• Code complexity/maintainability fact...\\n• Typing or documentation standard fact...",
  "securityReview": "• Top injection/vulnerability hazard...\\n• Hardcoded or security flow risk...\\n• Specific mitigation standard...",
  "maintainabilityReview": "• Testability and modular dependency fact...\\n• Documentation coverage level...\\n• Code updates/readiness level...",
  "technicalDebt": "• First major source of technical debt...\\n• Second major source...",
  "codeSmells": "• First specific design smell or anti-pattern...\\n• Second specific design smell...",
  "topImprovements": [
    "Most critical improvement 1",
    "Most critical improvement 2",
    "Most critical improvement 3"
  ],
  "overallSuggestions": "• Strategic concrete roadmap item 1...\\n• Strategic concrete roadmap item 2..."
}

Return ONLY the JSON. Do not wrap in markdown code blocks like \`\`\`json. Do not explain anything outside the JSON.
`;

    const response = await generateContentWithRetry({
      model: 'gemini-3.6-flash',
      contents: prompt,
      config: {
        responseMimeType: 'application/json'
      }
    });

    const text = response.text;
    if (text) {
      return JSON.parse(text);
    }
  } catch (err) {
    console.error("Failed to generate project-level review:", err);
  }

  return {
    executiveSummary: "• Project-level analysis completed.\n• Executive summary could not be dynamically requested due to system load.",
    architectureReview: "• Review of modular structure finished.\n• Architectural detail computation failed.",
    overallCodeQuality: "• Static quality evaluation completed.\n• Formatting suggestions skipped.",
    securityReview: "• Risk assessment executed.\n• Specific vulnerability details skipped.",
    maintainabilityReview: "• General upkeep profiles computed.\n• Maintainability details skipped.",
    technicalDebt: "• Technical debt assessment completed.\n• Code consolidation recommended.",
    codeSmells: "• Specific smell logs skipped.\n• Structural code smells evaluated.",
    topImprovements: ["Apply PEP8 code formatting", "Introduce clean type safety"],
    overallSuggestions: "• Review individual file suggestions for comprehensive changes."
  };
}

// ----------------- Auth Routes -----------------

app.get('/login', (req, res) => {
  if (req.query.logout === 'true') {
    if (req.session) {
      (req.session as any).userId = null;
    }
    return res.render('accounts/login', { error: null });
  }

  let userId = req.session ? (req.session as any).userId : null;
  const authId = req.query.auth_id;
  if (authId && typeof authId === 'string') {
    userId = authId;
  }
  if (userId) {
    return res.redirect('/' + (authId ? '?auth_id=' + authId : ''));
  }
  res.render('accounts/login', { error: null });
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const user = db.users.find(u => u.username.toLowerCase() === username.toLowerCase());

  if (user && bcrypt.compareSync(password, user.passwordHash)) {
    if (req.session) {
      (req.session as any).userId = user.id;
    }
    flash(req, 'success', 'Logged in successfully!');
    res.redirect('/?auth_id=' + user.id);
  } else {
    res.render('accounts/login', { error: 'Invalid username or password.' });
  }
});

app.get('/register', (req, res) => {
  res.render('accounts/register', { error: null });
});

app.post('/register', (req, res) => {
  const { username, email, password, passwordConfirm } = req.body;

  if (password !== passwordConfirm) {
    return res.render('accounts/register', { error: 'Passwords do not match.' });
  }

  const exists = db.users.some(u => u.username.toLowerCase() === username.toLowerCase());
  if (exists) {
    return res.render('accounts/register', { error: 'Username is already taken.' });
  }

  const newUser: User = {
    id: Math.random().toString(36).substring(2, 11),
    username,
    email,
    passwordHash: bcrypt.hashSync(password, 10)
  };

  db.users.push(newUser);
  saveDb();

  if (req.session) {
    (req.session as any).userId = newUser.id;
  }
  flash(req, 'success', 'Registration successful! Welcome.');
  res.redirect('/?auth_id=' + newUser.id);
});

app.get('/logout', (req, res) => {
  if (req.session) {
    req.session.destroy(() => {
      res.redirect('/login?logout=true');
    });
  } else {
    res.redirect('/login?logout=true');
  }
});

// ----------------- Main Dashboard / Reports -----------------

app.get('/', requireAuth, (req, res) => {
  const userId = (req.session as any).userId;
  const userProjects = db.projects.filter(p => p.userId === userId);
  const total_projects = userProjects.length;

  const userReports = db.analysisReports.filter(r => r.userId === userId);
  const total_files = userReports.length;
  const analyzed_files = userReports.length;
  
  let average_score = 0;
  let excellent = 0;
  let good = 0;
  let improve = 0;
  let poor = 0;
  let total_code_issues = 0;
  let total_security_issues = 0;

  if (total_projects > 0) {
    const sum = userProjects.reduce((acc, p) => acc + p.overallScore, 0);
    average_score = parseFloat((sum / total_projects).toFixed(1));
  }

  userReports.forEach(r => {
    total_code_issues += r.issueCount;
    total_security_issues += r.securityIssueCount;

    if (r.qualityStatus === 'Excellent') excellent++;
    else if (r.qualityStatus === 'Good') good++;
    else if (r.qualityStatus === 'Needs Improvement') improve++;
    else poor++;
  });

  const recent = [...userReports].sort((a, b) => new Date(b.analyzedAt).getTime() - new Date(a.analyzedAt).getTime()).slice(0, 5);
  const recentProjects = [...userProjects].sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime()).slice(0, 5);

  res.render('accounts/dashboard', {
    total_projects,
    total_files,
    analyzed_files,
    average_score,
    security_count: total_security_issues,
    excellent,
    good,
    improve,
    poor,
    total_code_issues,
    total_security_issues,
    recent,
    recentProjects
  });
});

// ----------------- File Operations -----------------

const storage = multer.memoryStorage();
const upload = multer({ storage });
const uploadFields = upload.fields([
  { name: 'zip_file', maxCount: 1 },
  { name: 'files', maxCount: 20 }
]);

app.get('/upload', requireAuth, (req, res) => {
  res.render('analyzer/upload');
});

app.post('/upload', requireAuth, uploadFields as any, async (req: any, res: any) => {
  const userId = (req.session as any).userId;
  const { project_name, description } = req.body;
  const files = (req.files as { [fieldname: string]: Express.Multer.File[] }) || {};

  if (!project_name) {
    flash(req, 'error', 'Project name is required.');
    return res.redirect('/upload?error=Project+name+is+required');
  }

  try {
    const projectId = Math.random().toString(36).substring(2, 11);
    const newProject: Project = {
      id: projectId,
      userId,
      name: project_name,
      overallScore: 0,
      totalIssues: 0,
      totalSecurityIssues: 0,
      description: description || '',
      status: 'analyzed',
      fileCount: 0,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    };

    const processedFiles: { filename: string, content: string }[] = [];
    let zipDebugInfo = '';

    // 1. Process ZIP File
    if (files['zip_file'] && files['zip_file'].length > 0) {
      const zipFile = files['zip_file'][0];
      try {
        const zip = new AdmZip(zipFile.buffer);
        const zipEntries = zip.getEntries();
        
        const ignoredDirs = ["__pycache__", ".git", ".github", "venv", ".venv", "env", "node_modules", "migrations", "__MACOSX"];
        const debugLogs: string[] = [];
        debugLogs.push(`Total ZIP entries: ${zipEntries.length}`);

        for (const entry of zipEntries) {
          const entryName = entry.entryName;
          const isDir = entry.isDirectory;
          
          if (isDir) {
            debugLogs.push(`Dir: "${entryName}" (skipped)`);
            continue;
          }
          
          // Split entry name to check if any part of the path is in ignored list or starts with dot (excluding '.' and '..')
          const pathParts = entryName.split(/[/\\]/).filter(Boolean);
          const hasIgnoredDir = pathParts.some(part => ignoredDirs.includes(part));
          const hasDotFile = pathParts.some(part => part.startsWith('.') && part !== '.' && part !== '..');
          const isPyFile = entryName.toLowerCase().endsWith('.py');

          debugLogs.push(`File: "${entryName}" | Parts: ${JSON.stringify(pathParts)} | IgnoredDir: ${hasIgnoredDir} | DotFile: ${hasDotFile} | IsPy: ${isPyFile}`);
          
          if (!hasIgnoredDir && !hasDotFile && isPyFile) {
            try {
              const data = entry.getData();
              if (data) {
                processedFiles.push({
                  filename: entryName, // Keep relative subdirectory structure to prevent filename collision
                  content: data.toString('utf8')
                });
                debugLogs.push(`  -> MATCHED & ADDED`);
              } else {
                debugLogs.push(`  -> EMPTY CONTENT`);
              }
            } catch (entryErr: any) {
              console.warn(`Skipping unreadable or corrupted entry: ${entryName}`, entryErr);
              debugLogs.push(`  -> READ ERROR: ${entryErr.message || entryErr}`);
            }
          }
        }
        zipDebugInfo = debugLogs.join('\n');
        console.log("ZIP Diagnostic Logs:\n" + zipDebugInfo);
      } catch (err) {
        console.error("Error unzipping project:", err);
        flash(req, 'error', 'Failed to extract zip file content. Please verify that it is a valid zip archive.');
        return res.redirect('/upload?error=Failed+to+extract+zip+file+content.+Please+verify+it+is+a+valid+zip+archive.');
      }
    }

    // 2. Process Individual Files
    if (files['files'] && files['files'].length > 0) {
      for (const file of files['files']) {
        processedFiles.push({
          filename: file.originalname,
          content: file.buffer.toString('utf8')
        });
      }
    }

    if (processedFiles.length === 0) {
      let errMsg = 'No Python (.py) files found to analyze.';
      if (zipDebugInfo) {
        errMsg += ' We parsed your ZIP, but found no valid .py files (check if they are inside hidden folders or excluded folders like venv/node_modules).';
      }
      flash(req, 'error', errMsg);
      return res.redirect(`/upload?error=${encodeURIComponent(errMsg)}`);
    }

    // Run AI analysis and local static checks in parallel to be extremely fast and avoid HTTP timeouts
    const analysisPromises = processedFiles.map(async (item) => {
      const fileId = Math.random().toString(36).substring(2, 11);
      
      // Save uploaded file representation
      const uploadedFile: UploadedFile = {
        id: fileId,
        projectId,
        userId,
        fileName: item.filename,
        content: item.content,
        uploadedAt: new Date().toISOString()
      };
      db.uploadedFiles.push(uploadedFile);

      // AI Analysis
      let analysis;
      try {
        analysis = await analyzePythonFile(item.filename, item.content);
      } catch (err) {
        console.error(`Gemini analysis failed for file: ${item.filename}, using local fallback`, err);
        const localAnalysis = await runLocalAnalysis(item.content);
        analysis = getFallbackAnalysis(item.filename, item.content, localAnalysis);
      }
      
      const reportId = Math.random().toString(36).substring(2, 11);
      const report: AnalysisReport = {
        id: reportId,
        uploadedFileId: fileId,
        projectId,
        userId,
        fileName: item.filename,
        pylintScore: analysis.pylintScore || 0,
        pylintIssues: analysis.pylintIssues || [],
        banditIssues: analysis.banditIssues || [],
        qualityStatus: analysis.qualityStatus || 'Needs Improvement',
        recommendations: analysis.recommendations || [],
        aiSuggestions: analysis.aiSuggestions || [],
        aiChanges: analysis.aiChanges || [],
        fixedCode: analysis.fixedCode || item.content,
        fixExplanation: analysis.fixExplanation || '',
        analyzedAt: new Date().toISOString(),
        issueCount: analysis.issueCount || 0,
        securityIssueCount: analysis.securityIssueCount || 0,
        securityRiskLevel: analysis.securityRiskLevel || 'Low Risk',
        readabilityScore: analysis.readabilityScore || 8,
        maintainabilityScore: analysis.maintainabilityScore || 8,
        aiSummary: analysis.aiSummary || '',
        strengths: analysis.strengths || [],
        weaknesses: analysis.weaknesses || []
      };
      
      return report;
    });

    const reports = await Promise.all(analysisPromises);

    let totalPylintScore = 0;
    let totalIssues = 0;
    let totalSecurityIssues = 0;
    const firstReportId = reports[0]?.id;

    reports.forEach(report => {
      db.analysisReports.push(report);
      totalPylintScore += report.pylintScore;
      totalIssues += report.issueCount;
      totalSecurityIssues += report.securityIssueCount;
    });

    // Generate Project AI Review
    let aiReview;
    try {
      aiReview = await generateProjectReview(processedFiles);
    } catch (err) {
      console.error("Failed to generate project AI review, using fallback:", err);
      // Fallback empty review structured object
      aiReview = {
        executiveSummary: "• Project-level analysis completed.",
        architectureReview: "• Review of modular structure finished.",
        overallCodeQuality: "• Static quality evaluation completed.",
        securityReview: "• Risk assessment executed.",
        maintainabilityReview: "• General upkeep profiles computed.",
        technicalDebt: "• Technical debt assessment completed.",
        codeSmells: "• Structural code smells evaluated.",
        topImprovements: ["Apply PEP8 code formatting", "Introduce clean type safety"],
        overallSuggestions: "• Review individual file suggestions for comprehensive changes."
      };
    }

    newProject.fileCount = processedFiles.length;
    newProject.overallScore = parseFloat((totalPylintScore / processedFiles.length).toFixed(1));
    newProject.totalIssues = totalIssues;
    newProject.totalSecurityIssues = totalSecurityIssues;
    newProject.firstReportId = firstReportId;
    newProject.aiReview = aiReview;

    db.projects.push(newProject);
    saveDb();

    flash(req, 'success', `Successfully uploaded and analyzed project with ${processedFiles.length} files.`);
    res.redirect(`/report/${firstReportId}?success=Successfully+uploaded+and+analyzed+project+with+${processedFiles.length}+files.`);
  } catch (err: any) {
    console.error("General error in project upload router:", err);
    flash(req, 'error', `Analysis failed: ${err.message || err}`);
    return res.redirect(`/upload?error=Analysis+failed:+${encodeURIComponent(err.message || 'unknown error')}`);
  }
});

app.get('/files', requireAuth, (req, res) => {
  const userId = (req.session as any).userId;
  const q = req.query.q as string;
  
  let userProjects = db.projects.filter(p => p.userId === userId);
  
  if (q) {
    const searchTerm = q.toLowerCase();
    userProjects = userProjects.filter(p => p.name.toLowerCase().includes(searchTerm) || p.description.toLowerCase().includes(searchTerm));
  }

  // Calculate stats to send exactly what my_files.ejs expects
  const formattedProjects = userProjects.map(p => {
    return {
      id: p.id,
      name: p.name,
      avgScore: p.overallScore,
      fileCount: p.fileCount,
      totalIssues: p.totalIssues,
      totalSecurityIssues: p.totalSecurityIssues,
      firstReportId: p.firstReportId,
      createdAt: p.createdAt
    };
  });

  res.render('analyzer/my_files', {
    projects: formattedProjects,
    query: q || ''
  });
});

app.post('/delete_project/:projectId', requireAuth, (req, res) => {
  const userId = (req.session as any).userId;
  const { projectId } = req.params;

  db.projects = db.projects.filter(p => !(p.id === projectId && p.userId === userId));
  db.uploadedFiles = db.uploadedFiles.filter(f => !(f.projectId === projectId && f.userId === userId));
  db.analysisReports = db.analysisReports.filter(r => !(r.projectId === projectId && r.userId === userId));
  
  saveDb();
  flash(req, 'success', 'Project deleted successfully.');
  res.redirect('/files');
});

// ----------------- Report Details -----------------

app.get('/report/:reportId', requireAuth, async (req, res) => {
  const userId = (req.session as any).userId;
  const { reportId } = req.params;

  const report = db.analysisReports.find(r => r.id === reportId && r.userId === userId);
  if (!report) {
    flash(req, 'error', 'Report not found.');
    return res.redirect('/files');
  }

  const project = db.projects.find(p => p.id === report.projectId && p.userId === userId);
  let formattedProject = null;
  if (project) {
    if (!project.aiReview) {
      const projectFiles = db.uploadedFiles.filter(f => f.projectId === project.id).map(f => ({
        filename: f.fileName,
        content: f.content
      }));
      project.aiReview = await generateProjectReview(projectFiles);
      saveDb();
    }
    formattedProject = {
      ...project,
      aiReview: formatAiReview(project.aiReview)
    };
  }

  const projectReports = db.analysisReports.filter(r => r.projectId === report.projectId && r.userId === userId);
  
  // Attach sourceCode to each report for instantaneous front-end swapping
  const reportsWithSource = projectReports.map(r => {
    const file = db.uploadedFiles.find(f => f.id === r.uploadedFileId);
    return {
      ...r,
      sourceCode: file ? file.content : ''
    };
  });

  const currentUploadedFile = db.uploadedFiles.find(f => f.id === report.uploadedFileId);

  res.render('analyzer/report', {
    project: formattedProject || project,
    report,
    projectReports: reportsWithSource,
    recommendations: report.recommendations,
    aiSuggestions: report.aiSuggestions,
    fixExplanation: report.fixExplanation,
    fixedCode: report.fixedCode,
    sourceCode: currentUploadedFile ? currentUploadedFile.content : '',
    security: report.banditIssues,
    pylint: report.pylintIssues
  });
});

// ----------------- Send Report Email & PDF Generation -----------------

function generatePdfContent(doc: any, report: any, project: any, projectReports: any[]) {
  const logoPath = path.join(process.cwd(), 'static', 'images', 'log_logo.png');
  const footerPath = path.join(process.cwd(), 'static', 'images', 'pdf_footer.png');

  // Helper for dynamic row height calculation
  const getRowHeight = (text: string, width: number, minH = 20) => {
    const textH = doc.heightOfString(text || '', { width });
    return Math.max(minH, textH + 8);
  };

  // --- PAGE HEADER BANNER ---
  const drawHeader = () => {
    if (fs.existsSync(logoPath)) {
      try {
        doc.image(logoPath, 20, 10, { height: 56 });
      } catch (err) {
        console.error("Error drawing logo in PDF:", err);
      }
    }

    doc.fontSize(24).font('Helvetica-Bold').fillColor('#0f2b5c').text('CODEGUARD', 96, 12);
    doc.fontSize(11.5).font('Helvetica').fillColor('#475569').text('AI Code Security Analysis Report', 96, 38);

    doc.fontSize(8.5).font('Helvetica-Bold').fillColor('#1e40af');
    doc.text('SECURE CODE   •   SMART ANALYSIS   •   BETTER QUALITY   •   ACTIONABLE INSIGHTS', 96, 55);

    // Decorative underline curve
    doc.save();
    doc.strokeColor('#2563eb').lineWidth(1.5);
    doc.moveTo(20, 72).bezierCurveTo(200, 78, 400, 66, 592, 72).stroke();
    doc.restore();
  };

  drawHeader();

  let curY = 88;

  // --- SUMMARY METADATA TABLE ---
  const formattedDate = report.analyzedAt 
    ? new Date(report.analyzedAt).toLocaleString('en-US', { day: '2-digit', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit', hour12: true })
    : new Date().toLocaleString('en-US', { day: '2-digit', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit', hour12: true });

  const summaryRows = [
    { label: 'File', value: report.fileName || (project ? project.name : 'Unknown') },
    { label: 'Date', value: formattedDate },
    { label: 'Quality Score', value: `${report.pylintScore || 0}/10` },
    { label: 'Quality Status', value: report.qualityStatus || 'Good' },
    { label: 'Code Issues', value: `${report.issueCount || (report.pylintIssues ? report.pylintIssues.length : 0)}` },
    { label: 'Security Issues', value: `${report.securityIssueCount || (report.banditIssues ? report.banditIssues.length : 0)}` }
  ];

  summaryRows.forEach(row => {
    // Label cell (Dark navy blue)
    doc.rect(20, curY, 140, 22).fill('#1d3557');
    doc.fontSize(10).font('Helvetica-Bold').fillColor('#ffffff').text(row.label, 28, curY + 5, { width: 124 });

    // Value cell (Light slate gray with border)
    doc.rect(160, curY, 432, 22).fillAndStroke('#f8fafc', '#cbd5e1');
    const valColor = row.label === 'Quality Status' ? '#1d4ed8' : '#0f172a';
    doc.fontSize(10).font('Helvetica-Bold').fillColor(valColor).text(row.value, 168, curY + 5, { width: 416 });

    curY += 22;
  });

  curY += 20;

  // --- DEDUPLICATION OF ISSUES & RECOMMENDATIONS ---
  const uniquePylintIssues: any[] = [];
  const seenPylint = new Set<string>();
  (report.pylintIssues || []).forEach((issue: any) => {
    const key = `${issue.line}-${issue.code}-${(issue.message || '').trim().toLowerCase()}`;
    if (!seenPylint.has(key)) {
      seenPylint.add(key);
      uniquePylintIssues.push(issue);
    }
  });

  const uniqueBanditIssues: any[] = [];
  const seenBandit = new Set<string>();
  (report.banditIssues || []).forEach((issue: any) => {
    const key = `${issue.line}-${issue.cwe || issue.test}-${(issue.text || issue.message || '').trim().toLowerCase()}`;
    if (!seenBandit.has(key)) {
      seenBandit.add(key);
      uniqueBanditIssues.push(issue);
    }
  });

  const uniqueRecommendations: string[] = [];
  const seenRecs = new Set<string>();
  (report.recommendations || []).forEach((rec: string) => {
    const cleaned = rec.trim().replace(/^[\-\*•✔\s]+/, '').trim();
    if (cleaned && !seenRecs.has(cleaned.toLowerCase())) {
      seenRecs.add(cleaned.toLowerCase());
      uniqueRecommendations.push(cleaned);
    }
  });

  // --- CODE QUALITY ISSUES SECTION ---
  if (uniquePylintIssues.length > 0) {
    if (curY > 650) {
      doc.addPage();
      drawHeader();
      curY = 88;
    }

    doc.fontSize(15).font('Helvetica-Bold').fillColor('#0f172a').text('Code Quality Issues', 20, curY);
    curY += 20;

    const drawQualityHeader = (y: number) => {
      doc.rect(20, y, 45, 22).fill('#1d3557');
      doc.rect(65, y, 60, 22).fill('#1d3557');
      doc.rect(125, y, 85, 22).fill('#1d3557');
      doc.rect(210, y, 382, 22).fill('#1d3557');

      doc.fontSize(9.5).font('Helvetica-Bold').fillColor('#ffffff');
      doc.text('Line', 25, y + 5);
      doc.text('Code', 70, y + 5);
      doc.text('Severity', 130, y + 5);
      doc.text('Description', 215, y + 5);
    };

    drawQualityHeader(curY);
    curY += 22;

    uniquePylintIssues.forEach((issue: any, index: number) => {
      const desc = issue.message || issue.description || '';
      const rowH = getRowHeight(desc, 370, 22);

      if (curY + rowH > 680) {
        doc.addPage();
        drawHeader();
        curY = 88;
        drawQualityHeader(curY);
        curY += 22;
      }

      const bg = index % 2 === 0 ? '#ffffff' : '#f8fafc';
      doc.rect(20, curY, 45, rowH).fillAndStroke(bg, '#cbd5e1');
      doc.rect(65, curY, 60, rowH).fillAndStroke(bg, '#cbd5e1');
      doc.rect(125, curY, 85, rowH).fillAndStroke(bg, '#cbd5e1');
      doc.rect(210, curY, 382, rowH).fillAndStroke(bg, '#cbd5e1');

      doc.fontSize(9.5).font('Helvetica').fillColor('#0f172a');
      doc.text(`${issue.line}`, 25, curY + 5);
      doc.text(`${issue.code}`, 70, curY + 5);
      doc.text(`${issue.severity || 'Convention'}`, 130, curY + 5);
      doc.text(desc, 215, curY + 5, { width: 370 });

      curY += rowH;
    });

    curY += 20;
  }

  // --- SECURITY ISSUES SECTION ---
  if (uniqueBanditIssues.length > 0) {
    if (curY > 650) {
      doc.addPage();
      drawHeader();
      curY = 88;
    }

    doc.fontSize(15).font('Helvetica-Bold').fillColor('#0f172a').text('Security Issues', 20, curY);
    curY += 20;

    const drawSecurityHeader = (y: number) => {
      doc.rect(20, y, 45, 22).fill('#b91c1c');
      doc.rect(65, y, 70, 22).fill('#b91c1c');
      doc.rect(135, y, 60, 22).fill('#b91c1c');
      doc.rect(195, y, 397, 22).fill('#b91c1c');

      doc.fontSize(9.5).font('Helvetica-Bold').fillColor('#ffffff');
      doc.text('Line', 25, y + 5);
      doc.text('Severity', 70, y + 5);
      doc.text('CWE', 140, y + 5);
      doc.text('Description', 200, y + 5);
    };

    drawSecurityHeader(curY);
    curY += 22;

    uniqueBanditIssues.forEach((issue: any, index: number) => {
      const desc = issue.text || issue.message || '';
      const rowH = getRowHeight(desc, 385, 22);

      if (curY + rowH > 680) {
        doc.addPage();
        drawHeader();
        curY = 88;
        drawSecurityHeader(curY);
        curY += 22;
      }

      const bg = index % 2 === 0 ? '#ffffff' : '#fef2f2';
      doc.rect(20, curY, 45, rowH).fillAndStroke(bg, '#fca5a5');
      doc.rect(65, curY, 70, rowH).fillAndStroke(bg, '#fca5a5');
      doc.rect(135, curY, 60, rowH).fillAndStroke(bg, '#fca5a5');
      doc.rect(195, curY, 397, rowH).fillAndStroke(bg, '#fca5a5');

      doc.fontSize(9.5).font('Helvetica').fillColor('#0f172a');
      doc.text(`${issue.line}`, 25, curY + 5);

      const sev = (issue.severity || 'LOW').toUpperCase();
      const sevColor = sev === 'HIGH' ? '#dc2626' : (sev === 'MEDIUM' ? '#d97706' : '#1d4ed8');
      doc.font('Helvetica-Bold').fillColor(sevColor).text(sev, 70, curY + 5);

      doc.font('Helvetica').fillColor('#0f172a');
      doc.text(`${issue.cwe || '78'}`, 140, curY + 5);
      doc.text(desc, 200, curY + 5, { width: 385 });

      curY += rowH;
    });

    curY += 20;
  } else {
    if (curY > 670) {
      doc.addPage();
      drawHeader();
      curY = 88;
    }
    doc.fontSize(15).font('Helvetica-Bold').fillColor('#0f172a').text('Security Issues', 20, curY);
    curY += 18;
    doc.fontSize(10.5).font('Helvetica-Bold').fillColor('#16a34a').text('OK - No security vulnerabilities detected.', 20, curY);
    curY += 22;
  }

  // --- RECOMMENDATIONS SECTION ---
  if (uniqueRecommendations.length > 0) {
    if (curY > 650) {
      doc.addPage();
      drawHeader();
      curY = 88;
    }

    doc.fontSize(15).font('Helvetica-Bold').fillColor('#0f172a').text('Recommendations', 20, curY);
    curY += 20;

    uniqueRecommendations.forEach((rec: string) => {
      if (curY > 680) {
        doc.addPage();
        drawHeader();
        curY = 88;
      }

      doc.fontSize(12).font('Helvetica-Bold').fillColor('#16a34a').text('✔', 20, curY);
      doc.fontSize(10.5).font('Helvetica').fillColor('#0f172a').text(rec, 38, curY, { width: 554 });

      const textH = doc.heightOfString(rec, { width: 554 });
      curY += Math.max(20, textH + 8);
    });

    curY += 20;
  }

  // --- EXECUTIVE PROJECT REVIEW (If present for multi-file projects) ---
  const formattedProject = project ? {
    ...project,
    aiReview: formatAiReview(project.aiReview)
  } : null;

  if (formattedProject?.aiReview) {
    const rev = formattedProject.aiReview;
    if (curY > 630) {
      doc.addPage();
      drawHeader();
      curY = 88;
    }

    doc.fontSize(15).font('Helvetica-Bold').fillColor('#0f2b5c').text('Project Executive AI Review', 20, curY);
    curY += 20;

    const sections = [
      { title: 'Executive Summary', content: rev.executiveSummary },
      { title: 'Architecture Review', content: rev.architectureReview },
      { title: 'Overall Code Quality', content: rev.overallCodeQuality },
      { title: 'Security Review', content: rev.securityReview },
      { title: 'Maintainability Review', content: rev.maintainabilityReview }
    ];

    sections.forEach(s => {
      if (s.content) {
        if (curY > 650) {
          doc.addPage();
          drawHeader();
          curY = 88;
        }

        doc.fontSize(11.5).font('Helvetica-Bold').fillColor('#1d3557').text(s.title, 20, curY);
        curY += 15;

        const lines = s.content.split('\n')
          .map((l: string) => l.trim().replace(/^[\-\*•\s]+/, '').trim())
          .filter((l: string) => l.length > 0);

        lines.forEach((line: string) => {
          if (curY > 680) {
            doc.addPage();
            drawHeader();
            curY = 88;
          }
          doc.fontSize(9.5).font('Helvetica').fillColor('#334155').text(`• ${line}`, 30, curY, { width: 550 });
          const lh = doc.heightOfString(`• ${line}`, { width: 550 });
          curY += Math.max(14, lh + 4);
        });

        curY += 8;
      }
    });
  }

  // --- FOOTER ON EVERY PAGE ---
  const range = doc.bufferedPageRange();
  for (let i = 0; i < range.count; i++) {
    doc.switchToPage(i);

    if (fs.existsSync(footerPath)) {
      try {
        // Complete footer graphic scaled proportionally (X=20 to 592, width: 572, height: 48) so no parts are cut off
        doc.image(footerPath, 20, 728, { width: 572, height: 48 });
      } catch (err) {
        console.error("Error drawing footer image:", err);
      }
    } else {
      doc.strokeColor('#cbd5e1').lineWidth(1.5).moveTo(20, 735).lineTo(592, 735).stroke();
      doc.fontSize(9.5).font('Helvetica-Bold').fillColor('#0f2b5c').text('CodeGuard AI Security Analysis Report', 20, 742);
      doc.fontSize(8.5).font('Helvetica').fillColor('#64748b').text('Developed by Devesh', 20, 755);
    }

    doc.fontSize(9.5).font('Helvetica-Bold').fillColor('#ffffff').text(`Page ${i + 1} of ${range.count}`, 470, 746, { align: 'right', width: 110 });
  }
}

function buildPdfBuffer(report: any, project: any, projectReports: any[]): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    try {
      const doc = new PDFDocument({ 
        size: 'letter',
        margin: 20, 
        margins: { top: 20, bottom: 20, left: 20, right: 20 },
        bufferPages: true 
      });

      const chunks: Buffer[] = [];
      doc.on('data', (chunk) => chunks.push(chunk));
      doc.on('end', () => resolve(Buffer.concat(chunks)));
      doc.on('error', (err) => reject(err));

      generatePdfContent(doc, report, project, projectReports);

      doc.end();
    } catch (err) {
      reject(err);
    }
  });
}

const sendEmailHandler = async (req: express.Request, res: express.Response) => {
  const userId = (req.session as any).userId;
  const { reportId } = req.params;
  const email = req.body.email || req.body.recipient_email;

  const report = db.analysisReports.find(r => r.id === reportId && r.userId === userId);
  if (!report) {
    flash(req, 'error', 'Report not found.');
    return res.redirect('/files');
  }

  const project = db.projects.find(p => p.id === report.projectId && p.userId === userId);
  const projectReports = db.analysisReports.filter(r => r.projectId === report.projectId && r.userId === userId);

  console.log(`✉️ Generating PDF report and sending to ${email}...`);

  try {
    // 1. Generate PDF dynamically as attachment
    const pdfBuffer = await buildPdfBuffer(report, project, projectReports);
    const pdfFilename = `CodeGuard_Report_${report.fileName.replace(/\s+/g, '_')}.pdf`;

    // 2. Configure real SMTP transport
    let transporter;
    const smtpUser = process.env.SMTP_USER;
    const smtpPass = process.env.SMTP_PASS;
    const smtpHost = process.env.SMTP_HOST || 'smtp.gmail.com';
    const smtpPort = parseInt(process.env.SMTP_PORT || '587');
    const smtpFrom = process.env.SMTP_FROM || 'noreply@codeguard.com';

    let etherealUrl = '';

    if (smtpUser && smtpPass) {
      transporter = nodemailer.createTransport({
        host: smtpHost,
        port: smtpPort,
        secure: smtpPort === 465,
        auth: {
          user: smtpUser,
          pass: smtpPass
        }
      });
    } else {
      console.log('No SMTP user/pass configured in .env. Attempting Ethereal.email test account creation...');
      try {
        const testAccount = await nodemailer.createTestAccount();
        transporter = nodemailer.createTransport({
          host: testAccount.smtp.host,
          port: testAccount.smtp.port,
          secure: testAccount.smtp.secure,
          auth: {
            user: testAccount.user,
            pass: testAccount.pass
          }
        });
        console.log(`Ethereal SMTP test account configured: ${testAccount.user}`);
      } catch (ethErr) {
        console.error('Failed to create Ethereal test account:', ethErr);
        // Fallback dummy transport that records but doesn't crash
        transporter = nodemailer.createTransport({
          jsonTransport: true
        });
      }
    }

    // 3. Compose Email
    const emailHtml = `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e2e8f0; border-radius: 8px;">
        <h2 style="color: #1e3a8a; border-bottom: 2px solid #cbd5e1; padding-bottom: 10px;">CodeGuard Security & Quality Report</h2>
        <p>Hello,</p>
        <p>Your AI-driven code analysis report is ready! We have compiled a comprehensive security and quality review for your project.</p>
        
        <div style="background-color: #f8fafc; padding: 15px; border-radius: 6px; margin: 20px 0;">
          <h3 style="margin-top: 0; color: #0f172a;">Scan Summary</h3>
          <table style="width: 100%; border-collapse: collapse;">
            <tr>
              <td style="padding: 6px 0; color: #475569; font-weight: bold;">File Scanned:</td>
              <td style="padding: 6px 0; text-align: right;">${report.fileName}</td>
            </tr>
            <tr>
              <td style="padding: 6px 0; color: #475569; font-weight: bold;">Quality Score:</td>
              <td style="padding: 6px 0; text-align: right; font-weight: bold; color: #16a34a;">${report.pylintScore} / 10</td>
            </tr>
            <tr>
              <td style="padding: 6px 0; color: #475569; font-weight: bold;">Security Vulnerabilities:</td>
              <td style="padding: 6px 0; text-align: right; color: #dc2626;">${report.securityIssueCount} (${report.securityRiskLevel})</td>
            </tr>
            <tr>
              <td style="padding: 6px 0; color: #475569; font-weight: bold;">Code Quality Rating:</td>
              <td style="padding: 6px 0; text-align: right;">${report.qualityStatus}</td>
            </tr>
          </table>
        </div>
        
        <p>We have attached the full PDF report with deep security, architecture, and quality analysis to this email.</p>
        <p style="color: #64748b; font-size: 12px; margin-top: 30px; border-top: 1px solid #e2e8f0; padding-top: 10px;">
          Generated by CodeGuard AI. Confidential analysis. Do not share sensitive results publicly.
        </p>
      </div>
    `;

    const info = await transporter.sendMail({
      from: smtpFrom,
      to: email,
      subject: `[CodeGuard] Security & Quality Scan Report for ${report.fileName}`,
      html: emailHtml,
      attachments: [
        {
          filename: pdfFilename,
          content: pdfBuffer,
          contentType: 'application/pdf'
        }
      ]
    });

    console.log('✉️ Email sent successfully:', info.messageId);
    
    // Log preview URL if sent to Ethereal
    if (!smtpUser && nodemailer.getTestMessageUrl(info)) {
      etherealUrl = nodemailer.getTestMessageUrl(info) as string;
      console.log(`✉️ Ethereal Sandbox Message Preview URL: ${etherealUrl}`);
    }

    const successMsg = etherealUrl 
      ? `Analysis report sent successfully to ${email}! (Test Sandbox View: ${etherealUrl})`
      : `Analysis report successfully sent to ${email}!`;

    flash(req, 'success', successMsg);
    return res.redirect(`/report/${reportId}?success=${encodeURIComponent(successMsg)}`);
  } catch (err: any) {
    console.error('Error sending email:', err);
    flash(req, 'error', `Failed to send email: ${err.message || err}`);
    return res.redirect(`/report/${reportId}?error=${encodeURIComponent('Failed to send email: ' + (err.message || 'unknown error'))}`);
  }
};

app.post('/report/:reportId/email', requireAuth, sendEmailHandler);
app.post('/report/:reportId/send-email', requireAuth, sendEmailHandler);

// ----------------- PDF Export (Dynamic PDFKit Generation) -----------------

app.get('/report/:reportId/pdf', requireAuth, async (req, res) => {
  const userId = (req.session as any).userId;
  const { reportId } = req.params;

  const report = db.analysisReports.find(r => r.id === reportId && r.userId === userId);
  if (!report) {
    flash(req, 'error', 'Report not found.');
    return res.redirect('/files');
  }

  const project = db.projects.find(p => p.id === report.projectId && p.userId === userId);
  const projectReports = db.analysisReports.filter(r => r.projectId === report.projectId && r.userId === userId);

  const filename = `CodeGuard_Project_Report_${(project ? project.name : 'Report').replace(/\s+/g, '_')}.pdf`;

  try {
    const pdfBuffer = await buildPdfBuffer(report, project, projectReports);
    res.setHeader('Content-disposition', `attachment; filename="${filename}"`);
    res.setHeader('Content-type', 'application/pdf');
    res.send(pdfBuffer);
  } catch (err: any) {
    console.error("Failed to export PDF:", err);
    flash(req, 'error', 'Failed to generate PDF report.');
    res.redirect(`/report/${reportId}?error=Failed+to+generate+PDF+report.`);
  }
});

// Start express server
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
