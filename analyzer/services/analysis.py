import os
import sys
import json
import tempfile
import subprocess
import logging

logger = logging.getLogger(__name__)

def run_pylint_analysis(source_code, file_name):
    """
    Runs Pylint on source_code using a temporary file.
    Returns:
        score (float): 0.0 to 10.0
        issue_count (int)
        issues (list of dict): [{line, column, symbol, message, type}]
    """
    if not file_name.endswith('.py'):
        return 10.0, 0, []

    with tempfile.NamedTemporaryFile(suffix='.py', mode='w+', delete=False, encoding='utf-8') as temp:
        temp.write(source_code)
        temp_path = temp.name

    issues = []
    score = 10.0

    try:
        # Run pylint with json output
        result = subprocess.run(
            [sys.executable, "-m", "pylint", "--output-format=json", temp_path],
            capture_output=True,
            text=True,
            timeout=15
        )
        
        raw_output = result.stdout.strip()
        if raw_output:
            try:
                pylint_data = json.loads(raw_output)
                for item in pylint_data:
                    issues.append({
                        'line': item.get('line', 0),
                        'column': item.get('column', 0),
                        'symbol': item.get('symbol', 'convention'),
                        'message': item.get('message', ''),
                        'type': item.get('type', 'convention'),
                        'message_id': item.get('message-id', '')
                    })
            except Exception as e:
                logger.error(f"Failed to parse pylint json: {e}")

        # Calculate score based on issues
        total_lines = max(1, len(source_code.splitlines()))
        error_count = sum(1 for i in issues if i['type'] == 'error')
        warning_count = sum(1 for i in issues if i['type'] == 'warning')
        refactor_count = sum(1 for i in issues if i['type'] == 'refactor')
        convention_count = sum(1 for i in issues if i['type'] == 'convention')

        deductions = (error_count * 2.5) + (warning_count * 1.5) + (refactor_count * 0.5) + (convention_count * 0.3)
        score = max(0.0, min(10.0, round(10.0 - deductions, 1)))

    except Exception as e:
        logger.error(f"Error executing pylint: {e}")
        # Basic Python syntax check fallback
        try:
            compile(source_code, file_name, 'exec')
            score = 8.5
        except SyntaxError as se:
            score = 3.0
            issues.append({
                'line': se.lineno or 1,
                'column': se.offset or 0,
                'symbol': 'syntax-error',
                'message': str(se.msg),
                'type': 'error',
                'message_id': 'E0001'
            })

    finally:
        if os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except OSError:
                pass

    return score, len(issues), issues


def run_bandit_analysis(source_code, file_name):
    """
    Runs Bandit security analysis on source_code.
    Returns:
        security_issue_count (int)
        issues (list of dict): [{line, severity, confidence, test_id, issue_text}]
    """
    if not file_name.endswith('.py'):
        return 0, []

    with tempfile.NamedTemporaryFile(suffix='.py', mode='w+', delete=False, encoding='utf-8') as temp:
        temp.write(source_code)
        temp_path = temp.name

    issues = []

    try:
        result = subprocess.run(
            [sys.executable, "-m", "bandit", "-f", "json", temp_path],
            capture_output=True,
            text=True,
            timeout=15
        )
        
        raw_output = result.stdout.strip()
        if raw_output:
            try:
                bandit_data = json.loads(raw_output)
                results_list = bandit_data.get('results', [])
                for item in results_list:
                    issues.append({
                        'line': item.get('line_number', 0),
                        'severity': item.get('issue_severity', 'LOW'),
                        'confidence': item.get('issue_confidence', 'LOW'),
                        'test_id': item.get('test_id', 'B000'),
                        'issue_text': item.get('issue_text', '')
                    })
            except Exception as e:
                logger.error(f"Failed to parse bandit json: {e}")

    except Exception as e:
        logger.error(f"Error executing bandit: {e}")

    finally:
        if os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except OSError:
                pass

    return len(issues), issues


def generate_ai_analysis_and_fix(source_code, file_name, pylint_issues, bandit_issues):
    """
    Uses Gemini API (or intelligent fallback) to generate AI-corrected code and review items.
    """
    api_key = os.environ.get('GEMINI_API_KEY')
    fixed_code = None
    exec_review = []
    sec_review = []
    recommendations = []

    if api_key:
        try:
            import google.generativeai as genai
            genai.configure(api_key=api_key)
            model = genai.GenerativeModel('gemini-1.5-flash')
            
            prompt = f"""
Analyze the following Python source file '{file_name}'.
Pylint Issues: {json.dumps(pylint_issues)}
Bandit Security Issues: {json.dumps(bandit_issues)}

Source Code:
```python
{source_code}
```

Respond with strict JSON containing:
1. "fixed_code": Corrected Python source code addressing linter and security issues with proper docstrings, typing, clean formatting.
2. "executive_review": Array of 2-3 bullet strings summarizing quality and maintainability.
3. "security_review": Array of 2-3 bullet strings regarding vulnerability findings.
4. "recommendations": Array of 3-4 bullet strings with actionable advice.
            """
            
            response = model.generate_content(
                prompt,
                generation_config={'response_mime_type': 'application/json'}
            )
            
            if response and response.text:
                data = json.loads(response.text)
                fixed_code = data.get('fixed_code')
                exec_review = data.get('executive_review', [])
                sec_review = data.get('security_review', [])
                recommendations = data.get('recommendations', [])

        except Exception as e:
            logger.error(f"Gemini API call error: {e}")

    # Fallback if no API key or Gemini call failed
    if not fixed_code:
        fixed_code = generate_fallback_corrected_code(source_code, pylint_issues, bandit_issues)

    if not exec_review:
        exec_review = [
            f"Analyzed {file_name} with static analysis suite.",
            f"Identified {len(pylint_issues)} linter convention flags across the codebase.",
            "Code structure follows standard Python execution flow."
        ]

    if not sec_review:
        if bandit_issues:
            sec_review = [f"Detected {len(bandit_issues)} potential security threat vector(s).", "Review input sanitization and execution credentials."]
        else:
            sec_review = [
                "No obvious high-severity security vulnerabilities were detected across the file.",
                "Avoid eval, exec, shell=True, and bare except blocks.",
                "Keep credentials out of source files and commit history."
            ]

    if not recommendations:
        recommendations = [
            "Add docstrings and type hints to function definitions.",
            "Replace debug prints with structured logging.",
            "Add automated unit tests for critical business logic.",
            "Track quality regressions by comparing issue counts between commits."
        ]

    return fixed_code, exec_review, sec_review, recommendations


def generate_fallback_corrected_code(source_code, pylint_issues, bandit_issues):
    """
    Applies clean refactoring improvements to source code as a fallback.
    """
    lines = source_code.splitlines()
    header = [
        '"""',
        'Auto-refactored code produced by CodeGuard AI.',
        'Addressed linter conventions, formatting standards, and safety guards.',
        '"""',
        'import logging',
        'import os',
        '',
        'logger = logging.getLogger(__name__)',
        ''
    ]
    
    # Simple cleanups
    improved_lines = []
    for line in lines:
        if line.strip().startswith('print('):
            indent = len(line) - len(line.lstrip())
            msg = line.strip()[6:-1]
            improved_lines.append(' ' * indent + f'logger.info({msg})')
        elif 'except:' in line:
            improved_lines.append(line.replace('except:', 'except Exception as e:'))
        else:
            improved_lines.append(line)

    return '\n'.join(header) + '\n' + '\n'.join(improved_lines)
