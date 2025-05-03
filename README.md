# 🛡️ NIST Cybersecurity Vulnerability Dashboard

This project is a **Streamlit**-based interactive dashboard that visualizes and explores cybersecurity vulnerabilities from a processed NIST dataset.

It uses **Named Entity Recognition (NER)**, network analysis, and visualizations to provide insights into CVEs, severity levels, affected operating systems, attack vectors, software vulnerabilities, and relationships between entities.



---

## 🚀 Authors

- [Ananya Verma](https://github.com/Ananyaearth)
- [Manav Khambhayata](https://github.com/ManavKhambhayata)
- [Aniruddha Singh](https://github.com/extinct-anni)
- [Smarak Patnaik](https://github.com/smarak96)
- [Kanha Tayal](https://github.com/Kanhatayal)
  
---

## 📑 Features

- 📊 **CVSS Score Analysis**: Interactive histogram and scatter plots of vulnerabilities based on severity.
- 🛡️ **Attack Vector Analysis**: Visual breakdown of attack vectors and user interaction dependencies.
- 💻 **Affected OS Analysis**: Bar and pie charts showcasing vulnerabilities across operating systems and OS families.
- 🔍 **Vulnerability Details Analysis**: Analysis of different vulnerability types and commonly affected software.
- ☁️ **Word Cloud**: Visual summary of frequently affected software.
- 🕸️ **Dependency Graph**: Interactive graph showing relationships between vulnerabilities, operating systems, and software.
- 🧩 **Detailed Vulnerability View**: Select a CVE ID to view its complete metadata and properties.

---

## 📂 Project Structure

```
NIST-Database-Information-Extraction-Framework/
│
├── dashboard.py
├── requirements.txt
├── enhanced_cybersecurity_data.csv
└── README.md
```

---

## 🌐 Live Demo

This project is also deployed on **Streamlit Cloud**:  
🔗 [Live App Link](https://nist-database-information-extraction-framework.streamlit.app/)

---

## ⚡ Tech Stack

- Python 🐍
- Streamlit 🚀
- pandas, plotly, pyvis, networkx, matplotlib, wordcloud
- NER-based data enhancement (custom preprocessing)

---

