# AI Cyber Threat Platform — Project Architecture

## 1. Project Goal

This project is an AI-powered cybersecurity platform that analyzes URLs and determines whether they are likely to be legitimate or phishing.

The platform is being developed as a team project.

The final system will combine:

1. Machine Learning URL classification
2. Threat Intelligence
3. Rule-based security analysis
4. Database and scan history
5. React frontend
6. FastAPI backend

---

## 2. Current Architecture

```text
React Frontend
      |
      | HTTP POST /predict
      v
FastAPI Backend
      |
      +--------------------+
      |                    |
      v                    v
ML URL Classifier     Future Security Modules
      |                    |
      |                    |
      +---------+----------+
                |
                v
          Final Scan Result
                |
                v
          React Frontend