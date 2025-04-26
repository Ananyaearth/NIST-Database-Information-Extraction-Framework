import streamlit as st
import pandas as pd
import plotly.express as px
import networkx as nx
from pyvis.network import Network
import matplotlib.pyplot as plt
from collections import Counter
from wordcloud import WordCloud
import re

# Load the dataset
df = pd.read_csv("enhanced_cybersecurity_data.csv")

# Streamlit App
st.title("NIST Cybersecurity Vulnerability Dashboard")

# Sidebar for Filters
st.sidebar.header("Filters")
selected_os = st.sidebar.multiselect("Select Affected OS", options=df['cleaned_affected_os'].explode().unique())
selected_attack_vector = st.sidebar.multiselect("Select Attack Vector", options=df['attack_vector'].dropna().unique())
min_cvss = st.sidebar.slider("Minimum CVSS Score", 0.0, 10.0, 0.0)

# Filter the DataFrame
filtered_df = df.copy()
if selected_os:
    filtered_df = filtered_df[filtered_df['cleaned_affected_os'].apply(lambda x: any(os in x for os in selected_os) if isinstance(x, list) else False)]
if selected_attack_vector:
    filtered_df = filtered_df[filtered_df['attack_vector'].isin(selected_attack_vector)]
filtered_df = filtered_df[filtered_df['CVSS Score'] >= min_cvss]

# Section 1: CVSS Score Analysis
st.header("CVSS Score Analysis")
avg_cvss = filtered_df['CVSS Score'].mean()
st.metric("Average CVSS Score", round(avg_cvss, 2))
fig1 = px.histogram(filtered_df, x='CVSS Score', nbins=20, title="Distribution of CVSS Scores")
fig1.update_layout(bargap=0.1)
st.plotly_chart(fig1)
filtered_df['Severity'] = filtered_df['CVSS Score'].apply(lambda x: 'High' if x >= 7.0 else 'Medium' if x >= 4.0 else 'Low')
fig2 = px.scatter(filtered_df, x='CVE ID', y='CVSS Score', color='Severity',
                  title="CVSS Scores by CVE (Color-Coded by Severity)")
fig2.update_xaxes(tickangle=45)
st.plotly_chart(fig2)

# Section 2: Attack Vector Analysis
st.header("Attack Vector Analysis")
fig3 = px.histogram(filtered_df, x='attack_vector', title="Distribution of Attack Vectors")
st.plotly_chart(fig3)
fig4 = px.histogram(filtered_df, x='attack_vector', color='user_interaction',
                    title="Attack Vector vs. User Interaction")
st.plotly_chart(fig4)
heatmap_data = pd.crosstab(filtered_df['privileges_required'], filtered_df['confidentiality'])
fig5 = px.imshow(heatmap_data, text_auto=True, aspect="auto",
                 title="Heatmap: Privileges Required vs. Confidentiality Impact")
st.plotly_chart(fig5)

# Section 3: Affected OS Analysis
st.header("Affected OS Analysis")
filtered_df['cleaned_affected_os'] = filtered_df['cleaned_affected_os'].apply(lambda x: eval(x) if isinstance(x, str) else x)
os_counts = Counter(filtered_df['cleaned_affected_os'].explode().dropna())
fig6 = px.bar(x=list(os_counts.keys()), y=list(os_counts.values()),
              title="Vulnerabilities by Affected OS")
fig6.update_xaxes(tickangle=45)
st.plotly_chart(fig6)
filtered_df['os_families'] = filtered_df['os_metadata'].apply(lambda x: eval(x)['os_families'] if isinstance(x, str) else x)
os_family_counts = Counter(filtered_df['os_families'].explode().dropna())
fig7 = px.pie(names=list(os_family_counts.keys()), values=list(os_family_counts.values()),
              title="Proportion of Vulnerabilities by OS Family")
st.plotly_chart(fig7)

# Section 4: Vulnerability Details Analysis
st.header("Vulnerability Details Analysis")
filtered_df['vulnerability_type'] = filtered_df['enhanced_entities'].apply(lambda x: eval(x)['vulnerability_type'] if isinstance(x, str) else x)
vuln_types = Counter(filtered_df['vulnerability_type'].explode().dropna())
fig8 = px.bar(x=list(vuln_types.keys()), y=list(vuln_types.values()),
              title="Distribution of Vulnerability Types")
fig8.update_xaxes(tickangle=45)
st.plotly_chart(fig8)

# Word Cloud for Software
st.subheader("Commonly Affected Software")
filtered_df['software'] = filtered_df['enhanced_entities'].apply(lambda x: eval(x)['software'] if isinstance(x, str) else x)
software_list = filtered_df['software'].explode().dropna()
cleaned_software = []
for software in software_list:
    if isinstance(software, str) and len(software) > 2:
        software = re.sub(r'[^a-zA-Z0-9\s]', '', software).strip()
        if software:
            cleaned_software.append(software.lower())
cleaned_software = list(set(cleaned_software))
software_text = " ".join(cleaned_software)
wordcloud = WordCloud(width=800, height=400, background_color='white', min_font_size=10).generate(software_text)
plt.figure(figsize=(10, 5))
plt.imshow(wordcloud, interpolation='bilinear')
plt.axis('off')
st.pyplot(plt)

# Section 5: Dependency Graph
st.header("Vulnerability Relationships (Dependency Graph)")
max_nodes = st.slider("Number of CVEs to Display", min_value=10, max_value=100, value=50, step=10)
filtered_df = filtered_df.sort_values(by='CVSS Score', ascending=False)
net = Network(height="600px", width="100%", bgcolor="#ffffff", font_color="black", notebook=False)
severity_colors = {'High': 'red', 'Medium': 'orange', 'Low': 'green'}
df_subset = filtered_df.head(max_nodes)
for idx, row in df_subset.iterrows():
    cve_id = row['CVE ID']
    severity = row['Severity']
    os_list = eval(row['cleaned_affected_os']) if isinstance(row['cleaned_affected_os'], str) else row['cleaned_affected_os']
    software_list = eval(row['enhanced_entities'])['software'] if isinstance(row['enhanced_entities'], str) else row['enhanced_entities']['software']
    net.add_node(cve_id, label=cve_id, title=f"Severity: {severity}\nCVSS Score: {row['CVSS Score']}\nDescription: {row['cleaned_description']}", color=severity_colors.get(severity, 'gray'), size=15 if severity == 'High' else 10)
    if isinstance(os_list, list):
        for os in os_list:
            if os:
                net.add_node(os, label=os, title=f"OS: {os}", color='purple', size=10)
                net.add_edge(cve_id, os, title="Runs on")
    if isinstance(software_list, list):
        for software in software_list:
            if software:
                net.add_node(software, label=software, title=f"Software: {software}", color='blue', size=10)
                net.add_edge(cve_id, software, title="Affects")
net.force_atlas_2based()
html_content = net.generate_html()
st.components.v1.html(html_content, height=600)
st.markdown("""
**Legend:**
- **Red**: High Severity (CVSS ≥ 7.0)
- **Orange**: Medium Severity (CVSS 4.0–6.9)
- **Green**: Low Severity (CVSS < 4.0)
- **Purple**: Operating System
- **Blue**: Software
""")

# Section 6: Detailed View
st.header("Detailed Vulnerability View")
selected_cve = st.selectbox("Select a CVE ID", filtered_df['CVE ID'])
if selected_cve:
    cve_row = filtered_df[filtered_df['CVE ID'] == selected_cve].iloc[0]
    st.write(f"**Description**: {cve_row['cleaned_description']}")
    st.write(f"**CVSS Score**: {cve_row['CVSS Score']}")
    st.write(f"**Attack Vector**: {cve_row['attack_vector']}")
    st.write(f"**Affected OS**: {cve_row['cleaned_affected_os']}")
    enhanced_entities = eval(cve_row['enhanced_entities']) if isinstance(cve_row['enhanced_entities'], str) else cve_row['enhanced_entities']
    st.write(f"**Vulnerability Types**: {enhanced_entities['vulnerability_type']}")
    st.write(f"**Prerequisites**: {enhanced_entities['prerequisites']}")
    st.write(f"**Outcomes**: {enhanced_entities['outcomes']}")
    st.write(f"**Software**: {enhanced_entities['software']}")