import streamlit as st
import pandas as pd
import json
import matplotlib.pyplot as plt
import seaborn as sns
from datetime import datetime
from io import StringIO

# Set seaborn style
sns.set(style="whitegrid")

# Function to filter and extract relevant vulnerability data
def extract_vulnerability_data(file):
    raw_data = json.load(file)
    output = []

    for result in raw_data.get("Results", []):
        for vuln in result.get("Vulnerabilities", []):
            entry = {
                "id": vuln.get("VulnerabilityID", ""),
                "cvss": vuln.get("CVSS", {}).get("ghsa", {}).get("V3Score", ""),
                "publishedDate": vuln.get("PublishedDate", "")[:10],
                "cwe": vuln.get("CweIDs", [""])[0] if vuln.get("CweIDs") else ""
            }
            output.append(entry)

    return output

# Preprocessing the data for plotting
def preprocess_data(df):
    df['publishedDate'] = pd.to_datetime(df['publishedDate'], errors='coerce')
    df['cvss'] = pd.to_numeric(df['cvss'], errors='coerce')  # Convert CVSS to float
    df['Year'] = df['publishedDate'].dt.year
    df['Month'] = df['publishedDate'].dt.to_period('M')
    return df

# Streamlit dashboard
def main():
    st.title("🛡️ CVE Risk Prioritization Dashboard")
    st.write("Upload a `vulnerabilities.json` file. We’ll filter it and instantly show you trends and severity insights 😘")

    uploaded_file = st.file_uploader("Upload vulnerabilities.json", type="json")

    if uploaded_file:
        # Step 1: Filter and create intermediate data
        filtered_data = extract_vulnerability_data(uploaded_file)

        # Save filtered data locally (optional)
        with open("filtered_vulnerabilities.json", "w") as outfile:
            json.dump(filtered_data, outfile, indent=2)

        st.success("✅ Filtered vulnerabilities saved as filtered_vulnerabilities.json")

        # Step 2: Load into DataFrame
        df = pd.DataFrame(filtered_data)
        df = preprocess_data(df)

        st.subheader("📊 Sample of Filtered CVE Data")
        st.dataframe(df.head())

        # CVSS Score Trend Over Time
        st.subheader("📈 CVSS Score Trend Over Time")
        trend_df = df.groupby("Month")["cvss"].mean().reset_index()
        trend_df["Month"] = trend_df["Month"].astype(str)

        plt.figure(figsize=(10, 4))
        sns.lineplot(data=trend_df, x="Month", y="cvss", marker="o")
        plt.xticks(rotation=45)
        plt.ylabel("Average CVSS Score")
        plt.title("Average CVSS Score by Month")
        st.pyplot(plt.gcf())

        # Monthly Vulnerability Counts
        st.subheader("🗓️ Number of Vulnerabilities per Month")
        count_df = df.groupby("Month")["id"].count().reset_index(name="count")
        count_df["Month"] = count_df["Month"].astype(str)

        plt.figure(figsize=(10, 4))
        sns.barplot(data=count_df, x="Month", y="count")
        plt.xticks(rotation=45)
        plt.ylabel("Number of Vulnerabilities")
        plt.title("Monthly Vulnerability Counts")
        st.pyplot(plt.gcf())

        # Critical Vulnerabilities (CVSS > 7)
        st.subheader("🔥 Critical Vulnerabilities per Month (CVSS > 7)")
        critical_df = df[df["cvss"] > 7]
        crit_count_df = critical_df.groupby("Month")["id"].count().reset_index(name="critical_count")
        crit_count_df["Month"] = crit_count_df["Month"].astype(str)

        plt.figure(figsize=(10, 4))
        sns.lineplot(data=crit_count_df, x="Month", y="critical_count", marker="o", color='red')
        plt.xticks(rotation=45)
        plt.ylabel("Critical Vulnerabilities")
        plt.title("Monthly Critical Vulnerabilities")
        st.pyplot(plt.gcf())

        # CWE Analysis
        st.subheader("🛠️ Most Common CWEs (Software Weaknesses)")
        cwe_counts = df["cwe"].value_counts().head(10).reset_index()
        cwe_counts.columns = ["CWE", "Count"]

        plt.figure(figsize=(8, 4))
        sns.barplot(data=cwe_counts, x="Count", y="CWE", palette="mako")
        plt.xlabel("Count")
        plt.ylabel("CWE")
        plt.title("Top 10 Common Software Weaknesses (CWEs)")
        st.pyplot(plt.gcf())

if __name__ == "__main__":
    main()
