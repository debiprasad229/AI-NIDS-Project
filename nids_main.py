# nids_main.py
# [cite_start]Reconstructed based on requirements in Technical Implementation Manual [cite: 30-36, 45, 61-62]

import streamlit as st
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score

# Page Configuration
st.set_page_config(page_title="AI-NIDS Dashboard", layout="wide")

st.title("🛡️ AI-Powered Network Intrusion Detection System")
st.markdown("### Real-Time Network Traffic Monitoring & Analysis")

# [cite_start]1. Data Management Strategy: Production Mode [cite: 47-53]
# Loading real-world CIC-IDS2017 cybersecurity data
@st.cache_data
def load_data():
    filename = 'Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv'

    try:
        df = pd.read_csv(filename)
    except FileNotFoundError:
        st.error(f"❌ Error: The file '{filename}' was not found.")
        st.info("Make sure the CSV file is in the same folder as this script.")
        st.stop()

    # Data Cleaning
    df.columns = df.columns.str.strip()
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.dropna(inplace=True)

    # Encoding Labels BEFORE feature selection
    df['Attack_Label'] = df['Label'].apply(lambda x: 0 if 'BENIGN' in str(x).upper() else 1)

    # Rename columns to match the Simulator inputs
    # We map the technical CSV columns to our Dashboard's simple inputs
    column_mapping = {
        'Total Length of Fwd Packets': 'Packet_Size',
        'Flow Duration': 'Duration',
        'Destination Port': 'Protocol',
        'Total Fwd Packets': 'Byte_Rate'
    }
    df.rename(columns=column_mapping, inplace=True)

    # Select ONLY the 4 features used in the Simulator + the Label
    # meaningful order: Packet_Size, Duration, Protocol, Byte_Rate
    required_columns = ['Packet_Size', 'Duration', 'Protocol', 'Byte_Rate', 'Attack_Label']
    
    # Verify columns exist
    missing_cols = [c for c in required_columns if c not in df.columns]
    if missing_cols:
        st.error(f"Missing columns: {missing_cols}")
        st.stop()

    return df[required_columns]

df = load_data()

# Temporary Helper: Print an attack example to the terminal
print("\n--- ATTACK EXAMPLE FOR TESTING ---")
attack_row = df[df['Attack_Label'] == 1].iloc[0]
print(attack_row)
print("----------------------------------\n")

# Sidebar - Operational Workflow 
st.sidebar.header("Operational Control")

# 2. Model Training 
# Initialize Random Forest Classifier 
if st.sidebar.button("Train Model Now"):
    st.sidebar.success("Initializing Training...")
    
    # Data Preprocessing
    X = df.drop('Attack_Label', axis=1)
    y = df['Attack_Label']
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)
    
    # Train Model
    clf = RandomForestClassifier(n_estimators=100)
    clf.fit(X_train, y_train)
    
    # Save model to session state so it persists
    st.session_state['model'] = clf
    st.session_state['accuracy'] = accuracy_score(y_test, clf.predict(X_test))
    
    st.sidebar.markdown(f"**Training Complete!**")
    st.sidebar.markdown(f"Accuracy: `{st.session_state['accuracy']:.2%}`")

# [cite_start]Main Dashboard View [cite: 60]
col1, col2 = st.columns(2)

with col1:
    st.subheader("Historical Traffic Data")
    # Add a checkbox to toggle between Normal and Attack data
    if st.checkbox("Show Attack Examples Only"):
        # Filter to show only rows where Attack_Label is 1
        st.dataframe(df[df['Attack_Label'] == 1].head(10))
    else:
        # Show the first 10 rows (mostly Normal)
        st.dataframe(df.head(10))

with col2:
    st.subheader("Traffic Distribution")
    st.bar_chart(df['Attack_Label'].value_counts())

st.markdown("---")

# 3. Live Simulation 
st.header("🚦 Live Traffic Simulator")
st.write("Input packet parameters below to test detection capabilities.")

c1, c2, c3, c4 = st.columns(4)
p_size = c1.number_input("Packet Size (Bytes)", min_value=0, max_value=2000, value=500)
duration = c2.number_input("Duration (sec)", min_value=0.0, value=1.5)
protocol = c3.number_input("Protocol (Port)", min_value=0, value=80)
byte_rate = c4.number_input("Byte Rate", min_value=0, value=1200)

if st.button("Analyze Packet"):
    if 'model' in st.session_state:
        # Prediction
        input_data = [[p_size, duration, protocol, byte_rate]]
        prediction = st.session_state['model'].predict(input_data)[0]
        
        if prediction == 1:
            st.error("🚨 ALERT: Malicious Traffic Detected!")
        else:
            st.success("✅ Traffic Status: Normal")
    else:
        st.warning("Please train the model using the Sidebar button first.")