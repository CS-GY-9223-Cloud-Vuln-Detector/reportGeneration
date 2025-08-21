
<img width="1620" height="1150" alt="image" src="https://github.com/user-attachments/assets/98e6a62b-a006-4525-b579-5cb80a69c42e" />

# Cloud-Based Source Code Vulnerability Detector

A cloud-native system for **detecting security vulnerabilities** in Python-based GitHub repositories and generating **developer-friendly reports**. The platform combines **static analysis** (Bandit) with **AI-driven fix suggestions** (LLaMA 3.2 3B model), and presents results in both **JSON** (for programmatic use) and **PDF** (for human review).

## 🚀 Features

* **Automated Repository Scanning**

  * Input a GitHub repository URL, system clones and scans all Python files.
  * Vulnerabilities identified using **Bandit** and tagged with CWE IDs.

* **Report Generation (Core Focus)**

  * Aggregates scan results into **structured summaries**.
  * Computes project-level metrics: total files, vulnerabilities by severity/type.
  * **AI-Generated Fix Suggestions** using LLaMA model for each vulnerability.
  * Multi-format outputs:

    * **JSON** → Interactive frontend rendering, API consumption.
    * **PDF** → Human-readable, styled reports with summaries, details, and remediation guidance.

* **Frontend Integration**

  * Upload repository URL and view results instantly.
  * Display of vulnerabilities alongside suggested fixes.

* **Cloud-Native Architecture**

  * Modular microservices with Flask.
  * Storage: Amazon S3 + Supabase (PostgreSQL).
  * Asynchronous processing with Amazon SQS.

---

<img width="966" height="539" alt="image" src="https://github.com/user-attachments/assets/05192aa5-5764-465f-8147-2d139ec66430" />


## 🛠️ System Architecture

1. **User Interface** → Accepts GitHub repo URL, authenticates users.
2. **URL Parser** → Clones repo, extracts Python files, uploads to S3.
3. **Vulnerability Detection Service** → Runs Bandit, tags with CWE IDs.
4. **Report Generation Service (Highlighted)** →

   * Collects metadata + vulnerabilities from database.
   * Runs LLaMA for context-aware fix suggestions.
   * Generates **JSON** + **PDF** reports.
5. **API Layer** → Exposes endpoints for triggering scans and retrieving reports.
6. **Database Layer** → Stores metadata, vulnerabilities, and reports.

---

## 📖 Example Report

The **PDF report** includes:

* **Project Summary**: Repo name, scan timestamp, total files scanned.
* **Vulnerability Summary**: Count by severity (High, Medium, Low).
* **Detailed Findings**: File path, line number, CWE ID, Bandit message.
* **Fix Suggestions**: AI-generated recommendations (e.g., replace hardcoded secrets, parameterize queries).

> Example:
>
> * Vulnerability: Hardcoded password at `config.py:45`
> * CWE: CWE-259 (Use of Hard-coded Password)
> * Suggestion: “Store credentials in environment variables and load them securely at runtime.”

---

## ⚙️ Usage

1. Enter a GitHub repository URL in the frontend.
2. Wait for scan completion (\~20s for medium repos).
3. Download/view report in:

   * **Frontend dashboard (JSON rendering)**
   * **Styled PDF (ReportLab)**

---

## 🔮 Future Improvements

* Support for **JavaScript, Java** and other languages.
* **Email service** for automated report delivery.
* **Scheduled scans** for continuous monitoring.
* **Dynamic analysis** to complement static scanning.
* CI/CD integration for **real-time vulnerability detection**.

---
