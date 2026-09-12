You are working in an existing codebase. I want you to re-implement the current idea and improve it using my previous idea.

First, inspect the entire project before changing anything:
- Understand the existing architecture, features, UI, data flow, API usage, database schema, and authentication.
- Identify which parts belong to the current implementation and which parts may conflict with or support the previous idea.
- Check the existing git diff and do not overwrite unrelated user changes.
- Find the relevant files, components, routes, services, models, tests, and documentation.

Project context:
- Current idea: MailGuardian AI — a modern SaaS-styled, user-friendly email security platform (inspired by InboxGuardianAI) featuring clean responsive design, zero-storage privacy focus, dedicated authentication, live ingestion drag & drop, interactive AI chat assistant, and clear plain-language threat explanations.
- Previous idea: SecureX Forensic Intelligence Platform — a high-depth digital forensic investigation workbench built for SIH (Smart India Hackathon) and Cyber Crime Police Units, focused on deep RFC 5322 MIME deconstruction, cryptographic evidence chain-of-custody (SHA-256/MD5), SPF/DKIM/DMARC protocol verification, reverse MTA hop traversal, Origin IP Leaflet geolocation radar, multi-source OSINT threat intelligence (AbuseIPDB, VirusTotal, AlienVault OTX), APT campaign threat memory, and court-admissible PDF/JSON forensic dossiers.
- Main problem with the current implementation: The two ideas are partially separated. The current implementation excels at forensic file analysis of uploaded .eml files, but lacks live automated mailbox background polling/quarantine (IMAP/API), lacks AI Quishing (QR code) detection, lacks formal Section 65B Indian Evidence Act certification for law enforcement, and needs complete unification of the sleek InboxGuardianAI SaaS UX with the deep technical forensic engine without any pricing sections.
- Desired result: A unified, production-ready Dual-Purpose Email Threat Defense & Digital Forensic Platform:
  1. For End-Users & Enterprises: Automated protection, clean SaaS dashboard, plain-language translations, zero data retention, and instant scam/phishing detection.
  2. For SOC Analysts & Cyber Crime Police (SIH Grand Finale): Deep 10-step forensic pipeline, reverse MTA hop origin radar, SPF/DKIM/DMARC crypto checks, tamper-proof court-admissible PDF dossiers with Section 65B certification, and context-grounded AI investigation chat.
- Target users:
  1. SIH Evaluators & Cyber Security Judges (Ministry of Home Affairs / I4C / CERT-In).
  2. Enterprise SOC Teams (L1/L2 Security Analysts & Incident Responders).
  3. Digital Forensic Investigators & Cyber Crime Police Officers.
  4. Non-technical corporate employees and families needing automated phishing defense.
- Required platform/stack: Web Application & RESTful API (Python FastAPI Backend + Tailwind CSS / Vanilla JS / Leaflet.js Frontend + SQLite Database).
- Preferred technologies: Python 3.10+, FastAPI, Uvicorn, SQLite3, ReportLab Platypus, dnspython, email-validator, beautifulsoup4, Tailwind CSS, Leaflet.js, FontAwesome 6, Google Gemini API with offline heuristic fallback.
- Constraints:
  1. Privacy-First: Zero permanent storage of raw email body contents (transient memory processing).
  2. RFC Protocol Compliance: Strict adherence to RFC 5322 (MIME), RFC 7208 (SPF), RFC 6376 (DKIM), and RFC 7489 (DMARC).
  3. Offline & Air-Gapped Resiliency: Fallbacks for sandboxed/offline environments if external threat feeds or LLM APIs are unreachable.
  4. Court Admissibility: Tamper-evident SHA-256/MD5 chain of custody and Section 65B legal formatting.
  5. Strictly NO pricing tables, tiers, or billing buttons anywhere in the interface.

Your job:

1. Compare the current idea with the previous idea.
2. Preserve useful existing functionality, but remove or refactor parts that no longer support the final direction.
3. Create a clear implementation plan before editing:
   - Product behavior
   - User flows
   - UI changes
   - Backend/API changes
   - Database/data-model changes
   - Authentication and authorization changes
   - Migration or backward-compatibility requirements
   - Testing strategy
4. Identify ambiguities and make reasonable assumptions. Record those assumptions clearly.
5. Implement the feature completely in the existing project. Do not create a disconnected demo or mock implementation unless the project architecture requires temporary mocks.
6. Follow the existing coding style and design system where appropriate.
7. Keep the implementation maintainable:
   - Reuse existing components and utilities.
   - Avoid duplicated logic.
   - Add validation and useful error handling.
   - Handle loading, empty, success, and failure states.
   - Protect sensitive data and user permissions.
   - Ensure responsive behavior on desktop and mobile.
8. Update any required:
   - Routes
   - Navigation
   - Components
   - Services
   - API endpoints
   - Database schema
   - Environment configuration
   - Types/interfaces
   - Tests
   - Documentation
9. Add or update tests for the main user flows and edge cases.
10. Run the relevant formatter, linter, type checker, and test suite.
11. Fix all errors caused by your changes.
12. Review the final diff for regressions, security issues, duplicated code, and incomplete states.

Important rules:
- Do not delete existing functionality unless it conflicts with the new direction or is explicitly obsolete.
- Do not invent external APIs, environment variables, or database behavior without checking the project first.
- Do not silently change unrelated files.
- Do not use placeholder buttons or unfinished TODO implementations.
- Do not claim something works unless you verified it.
- If a requirement is impossible or unclear, explain the issue and choose the safest practical implementation.
- If the existing implementation is better than the proposed change in a specific area, preserve it and explain why.

At the end, provide:
- A concise summary of what changed.
- The main files changed.
- Any database or environment changes.
- Tests and commands run, including their results.
- Assumptions made.
- Known limitations or remaining risks.
- Suggested next steps, only if they are genuinely necessary.
