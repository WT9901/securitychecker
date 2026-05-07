# Login and Registration Security Checker

The project intentionally focuses on vulnerabilities that users or attackers can exploit through application behavior. It does not focus on dependency or library vulnerability analysis in this scope.

The app has two main parts:

1. Requirement Intelligence Module: Takes login/registration requirements, maps them to selected OWASP risks, and generates abuse cases. It analyzes login and registration from a security perspective.

It maps each requirement to user-exploitable OWASP risks in authentication workflows. The current scope focuses on:

- A03: Injection
- A07: Identification and Authentication Failures
- A01: Broken Access Control

2. Implementation Validation Module: Accepts a target login/register URL and runs practical validation checks. Current checks include target URL safety validation, connectivity/status review, selected security header checks, and cookie flag checks.

## Features

- Accepts a functional requirement sentence from a user.
- Maps requirement keywords to selected OWASP risks:
  - A03: Injection
   - A07: Identification and Authentication Failures
   - A01: Broken Access Control
- Generates context-specific possible attacks for each matched risk.
- Adds confidence scoring (Low/Medium/High) for each mapped risk.
- Uses safe input validation and escaped output in the UI.
- Includes an active Implementation Validation workflow for target URL checks.
- Supports JSON evidence export for latest analysis and validation outputs.
- Supports PDF report export for professional documentation and submission.
- Stores validation history locally for traceability.

## Run

1. Create a virtual environment (optional but recommended).
2. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```

3. Start the app:

   ```bash
   python app.py
   ```

4. Open:

   ```
   http://127.0.0.1:5000
   ```

## Security Notes

- Input length validation and control-character stripping.
- UI output is escaped by Flask/Jinja auto-escaping.
- No dynamic code execution or direct database queries.
- The scope prioritizes exploitable authentication and authorization weaknesses.
