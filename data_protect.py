import streamlit as st
import hashlib
import json
import os
from cryptography.fernet import Fernet

DATA_PATH = 'user_data.json'

# Generate/load a Fernet key (for demo, regenerated each run)
if "crypto_key" not in st.session_state:
    st.session_state.crypto_key = Fernet.generate_key()
fernet = Fernet(st.session_state.crypto_key)

# Data persistence helpers
def read_data():
    if os.path.exists(DATA_PATH):
        with open(DATA_PATH, 'r') as file:
            return json.load(file)
    return {}

def write_data(data):
    with open(DATA_PATH, 'w') as file:
        json.dump(data, file)

if "vault" not in st.session_state:
    st.session_state.vault = read_data()

if "attempts" not in st.session_state:
    st.session_state.attempts = 0

# Passkey hashing
def get_hash(passphrase):
    return hashlib.sha256(passphrase.encode()).hexdigest()

# Encryption
def lock_text(plain, passphrase):
    return fernet.encrypt(plain.encode()).decode()

# Decryption
def unlock_text(ciphertext, passphrase):
    hashed = get_hash(passphrase)
    entry = st.session_state.vault.get(ciphertext)
    if entry and entry["passkey"] == hashed:
        st.session_state.attempts = 0
        return fernet.decrypt(ciphertext.encode()).decode()
    else:
        st.session_state.attempts += 1
        return None

# Streamlit UI
st.title("🛡️ Personal Data Vault")

pages = ["Home", "Add Secret", "Unlock Secret", "Reauthorize"]
nav = st.sidebar.selectbox("Go to", pages)

if nav == "Home":
    st.header("Welcome to Your Personal Data Vault")
    st.write("Safeguard your notes or secrets with a passphrase. Encrypt and decrypt with confidence!")

elif nav == "Add Secret":
    st.header("🔐 Store a New Secret")
    secret = st.text_area("Type your secret here:")
    passphrase = st.text_input("Choose a passphrase:", type="password")

    if st.button("Encrypt & Store"):
        if secret and passphrase:
            hashed = get_hash(passphrase)
            encrypted = lock_text(secret, passphrase)
            st.session_state.vault[encrypted] = {
                "encrypted_text": encrypted,
                "passkey": hashed
            }
            write_data(st.session_state.vault)
            st.success("Your secret is locked away safely!")
            st.code(encrypted, language="text")
        else:
            st.warning("Please provide both a secret and a passphrase.")

elif nav == "Unlock Secret":
    if st.session_state.attempts >= 3:
        st.warning("🚫 Too many failed tries! Please reauthorize.")
        st.session_state.attempts = 0
        st.experimental_rerun()

    st.header("🔓 Unlock a Secret")
    encrypted = st.text_area("Paste your encrypted text:")
    passphrase = st.text_input("Enter your passphrase:", type="password")

    if st.button("Decrypt"):
        if encrypted and passphrase:
            revealed = unlock_text(encrypted, passphrase)
            if revealed:
                st.success(f"Here is your secret: {revealed}")
            else:
                left = 3 - st.session_state.attempts
                st.error(f"Wrong passphrase! Attempts left: {left}")
                if st.session_state.attempts >= 3:
                    st.warning("🚫 Too many failed tries! Please reauthorize.")
                    st.experimental_rerun()
        else:
            st.warning("Both fields are required.")

elif nav == "Reauthorize":
    st.header("🔑 Reauthorize Access")
    master = st.text_input("Enter master password:", type="password")
    if st.button("Login"):
        if master == "admin123":  # Demo master password
            st.session_state.attempts = 0
            st.success("Access restored! You can try unlocking secrets again.")
            st.experimental_rerun()
        else:
            st.error("Master password incorrect.")