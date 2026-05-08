# 🛡️ Gaurdly | URL Intelligence Platform

A sophisticated AI-powered URL analysis tool that helps you identify malicious links and phishing attempts before they cause harm. Gaurdly uses machine learning to analyze URLs and provide real-time risk assessments.

## ✨ Features

- **Real-time URL Analysis**: Instantly scan any URL for potential threats
- **48-Feature Engine**: Comprehensive analysis using multiple heuristics and metrics
- **Risk Scoring**: Get a 0-100 risk score with detailed explanations
- **Technical Breakdown**: View detailed feature analysis and heuristics
- **Domain Intelligence**: WHOIS data and security flag analysis
- **Modern UI**: Clean, professional interface built with Streamlit
- **Trusted Whitelist**: Pre-vetted safe domains for reduced false positives

## 🚀 Quick Start

### Prerequisites

- Python 3.8 or higher
- pip package manager

### Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd Gaurdly
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Run the application:
```bash
streamlit run app.py
```

The application will open in your default web browser at `http://localhost:8501`

## 📋 Dependencies

- `streamlit>=1.35.0` - Web application framework
- `pandas>=2.0.0` - Data manipulation
- `numpy>=1.24.0` - Numerical computing
- `plotly>=5.18.0` - Interactive visualizations
- `scikit-learn>=1.3.0` - Machine learning
- `joblib>=1.3.0` - Model serialization
- `requests>=2.31.0` - HTTP requests
- `python-whois>=0.8.0` - WHOIS lookup
- `tldextract>=5.1.1` - Domain extraction
- `imbalanced-learn>=0.11.0` - ML utilities

## 🧠 How It Works

Gaurdly uses a sophisticated machine learning pipeline to analyze URLs:

1. **Feature Extraction**: Extracts 48 different features from each URL including:
   - Length-based metrics (URL length, domain length, path length)
   - Character analysis (digits, letters, special characters)
   - Structural analysis (subdomains, query parameters)
   - Security indicators (HTTPS, IP addresses, suspicious TLDs)
   - Entropy calculations for randomness detection

2. **Machine Learning**: Uses a Random Forest classifier trained on malicious vs. benign URLs

3. **Risk Assessment**: Provides a 0-100 risk score with confidence levels

4. **Additional Intelligence**: WHOIS lookup and security flag analysis

## 🎯 Use Cases

- **Email Security**: Check links in suspicious emails
- **Browser Protection**: Verify URLs before clicking
- **Security Training**: Educational tool for phishing awareness
- **API Integration**: Can be integrated into other security tools
- **Research**: URL analysis and threat intelligence

## 🖥️ Interface

The application features four main sections:

1. **Scanner**: Main URL analysis interface
2. **Technical Analysis**: Detailed feature breakdown and visualizations
3. **Domain Intel**: WHOIS data and security flags
4. **Help Center**: FAQ and usage guidance

## 🔧 Configuration

### Model Files

- `malicious_url_rf_model.pkl`: Pre-trained Random Forest model
- `feature_names.json`: Feature configuration file

### Trusted Domains

The application maintains a whitelist of trusted domains including:
- Major tech companies (Google, Microsoft, Apple)
- Social media platforms (Facebook, Instagram, YouTube)
- Educational domains (.edu)
- And other legitimate services

## 🛠️ Development

### Project Structure

```
Gaurdly/
├── app.py                 # Main application file
├── requirements.txt       # Python dependencies
├── malicious_url_rf_model.pkl  # ML model
├── feature_names.json    # Feature configuration
├── .streamlit/          # Streamlit configuration
└── README.md            # This file
```

### Customization

- **Add trusted domains**: Modify the `TRUSTED_DOMAINS` set in `app.py`
- **Adjust risk threshold**: Modify the probability threshold in the prediction logic
- **Feature tuning**: Update the feature extraction function as needed

## ⚠️ Disclaimer

While Gaurdly provides sophisticated URL analysis, no security tool is 100% perfect. Always exercise caution when clicking unfamiliar links, and use additional security measures when handling sensitive information.

## 📄 License

This project is provided for educational and research purposes. Please check the license file for specific usage terms.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues for bugs and feature requests.

## 📞 Support

For questions or support, please refer to the Help Center section within the application or open an issue in the repository.

---

**Built with using Streamlit and Machine Learning**
