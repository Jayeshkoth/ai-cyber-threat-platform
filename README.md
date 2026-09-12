
# AI Cyber Threat Intelligence and Attack Prediction Platform

An AI-powered cybersecurity platform that analyzes URLs using machine learning, security analysis, threat intelligence, and attack prediction.

## Project Goal

The platform analyzes a given URL and combines multiple security signals to determine whether it is likely to be legitimate or phishing. For suspicious URLs, it also identifies the most likely attack category based on the available evidence.

## Features

### Machine Learning
- URL feature extraction
- Phishing URL classification
- Random Forest machine learning model
- Phishing and legitimate probability
- Prediction confidence

### Security Analysis
- Rule-based URL security analysis
- Suspicious URL indicators
- Security risk score
- Security findings

### Threat Intelligence
- VirusTotal integration
- PhishTank integration
- URL reputation checking
- Blacklist status
- Provider-level results
- Safe handling of unavailable threat-intelligence providers

### Attack Prediction
- Credential Theft
- Banking Phishing
- Cryptocurrency Scam
- Malicious Redirect
- Suspicious Infrastructure
- Generic Phishing
- Benign

The attack prediction system combines machine-learning results, security indicators, risk score, and threat-intelligence evidence to determine the most likely attack category. It does not claim to predict a specific future attack.

### Alerts
- Automatic security alert generation
- Alert severity classification
- Risk score and prediction included in alerts
- Dashboard alert history

### Database and Analytics
- Scan history
- Individual scan details
- Scan statistics
- Threat history
- Threat trends
- Time-range filtering
- Repeated URL detection
- Increased-risk URL detection
- Attack category distribution

### Web Interface
- React frontend
- URL scanning interface
- Combined analysis results
- Attack prediction results
- Threat-intelligence results
- Security alerts
- Historical scan dashboard
- Interactive threat-trend chart

## System Workflow

```text
User enters URL
       |
       v
Machine Learning Classification
       |
       +----------------------+
       |                      |
       v                      v
Security Analysis      Threat Intelligence
       |                      |
       +----------+-----------+
                  |
                  v
          Attack Prediction
                  |
                  v
             Risk Scoring
                  |
                  v
               Alerts
                  |
                  v
          Database / History
                  |
                  v
            React Dashboard