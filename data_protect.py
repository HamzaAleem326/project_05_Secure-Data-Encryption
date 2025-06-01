import streamlit as st
import hashlib
import json
import os
from cryptography.fernet import Fernet
import time

DATA_PATH = 'user_data.json'
LOCKOUT_DURATION = 60  # seconds

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

if "lockout_time" not in st.session_state:
    st.session_state.lockout_time = 0

if "authenicated_user" not in st.session_state:
    st.session_state.authenicated_user = None

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

# navigation bar
st.title("Data Protection System")
menu= ["Home", "register", "login","Store Data", "Retrive Data" ]
choice = st.sidebar.selectbox("Navigation", menu)  # fixed selectbox

if choice == "Home":
    st.subheader("Welcome to the Data Protection System")
    st.write("This system allows you to securely store and retrieve data using encryption with streamlit. this system also allows you to register and login with a password. The password is hashed and stored securely, and the data is encrypted using a key derived from the password.")

# registration
elif choice == "register":
    st.subheader("Register")
    username = st.text_input("Username")
    password = st.text_input("Password", type='password')
    
    if st.button("Register"):
        if username and password:
            if username in st.session_state.vault:
                st.error("Username already exists.")
            else:
                hashed_password = get_hash(password)
                st.session_state.vault[username] = {"password": hashed_password, "data": []}
                write_data(st.session_state.vault)
                st.success("Registration successful!")
        else:
            st.error("Please enter both username and password.")

elif choice == "login":
    st.subheader("Login")
    
    if time.time() < st.session_state.lockout_time:
        remaining_time = int(st.session_state.lockout_time - time.time())
        st.error(f"Too many failed attempts. Please try again in {remaining_time} seconds.")
        st.stop()
    username = st.text_input("Username")
    password = st.text_input("Password", type='password')

    if st.button("Login"):
        if username in st.session_state.vault and st.session_state.vault[username]["password"] == get_hash(password):
            st.session_state.authenicated_user = username
            st.session_state.attempts = 0
            st.success(f"Welcome {username}!")
        else:
            st.session_state.attempts += 1
            remaining_attempts = 3 - st.session_state.attempts
            st.error(f"Invalid credentials. {remaining_attempts} attempts remaining.")

            if st.session_state.attempts >= 3:
                st.session_state.lockout_time = time.time() + LOCKOUT_DURATION
                st.error("Too many failed attempts. You are locked out for 60 seconds.")
                st.stop()

# data storage

elif choice == "Store Data":
    if not st.session_state.authenicated_user:
        st.warning("Please log in to store data.")
    else:
        st.subheader('store Data')
        data = st.text_area("Enter data to store")
        passkey = st.text_input("Enter passkey", type='password')

        if st.button('encrypt and store'):
            if data and passkey:
                encrypted_data = lock_text(data, passkey)
                st.session_state.vault[st.session_state.authenicated_user]["data"].append({
                    "encrypted_text": encrypted_data,
                    "passkey": get_hash(passkey)
                })
                write_data(st.session_state.vault)
                st.success("Data stored successfully!")
            else:
                st.error("Please enter both data and passkey.")

# data retrieval

elif choice == "Retrive Data":
    if not st.session_state.authenicated_user:
        st.warning("Please log in to retrieve data.")
    else:
        st.subheader('Retrive Data')
        user_data = st.session_state.vault.get(st.session_state.authenicated_user, {}).get('data', [])

        if not user_data:
            st.info('No data found for the user.')
        else:
            st.write("Stored Data:")
            for i, item in enumerate(user_data):
                st.code(item["encrypted_text"], language='text')

        encrypted_input = st.text_area('enter encrypted data to decrypt')
        passkey = st.text_input("Enter passkey to decrypt", type='password')

        if st.button('Decrypt'):
            result = unlock_text(encrypted_input, passkey)
            if result:
                st.success(f"Decrypted Data: {result}")
            else:
                st.error("Decryption failed. Please check the passkey or the encrypted data.")