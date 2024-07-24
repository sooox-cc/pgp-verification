import streamlit as st
import pgpy
from pgpy.constants import PubKeyAlgorithm, KeyFlags, HashAlgorithm, SymmetricKeyAlgorithm, CompressionAlgorithm
import secrets

def generate_random_message():
    # Generate a random message
    return secrets.token_hex(16)

def encrypt_message(pubkey_text, message):
    # Load public key from text, encrypt a message with the public key
    try:
        pubkey = pgpy.PGPKey()
        pubkey.parse(pubkey_text)
        encrypted_message = pubkey.encrypt(pgpy.PGPMessage.new(message))
        return str(encrypted_message), None
    except Exception as e:
        return None, str(e)

st.title('PGP Encryption Demo')

if 'original_message' not in st.session_state:
    st.session_state.original_message = generate_random_message()

pubkey_text = st.text_area("Paste your PGP Public Key here:")
if pubkey_text:
    encrypted_message, error = encrypt_message(pubkey_text, st.session_state.original_message)
    if encrypted_message:
        st.text_area("Encrypted Message:", encrypted_message)

        decrypted_message = st.text_input("Enter the decrypted message:")
        # Trim any whitespaces and compare
        if decrypted_message.strip():
            if decrypted_message.strip() == st.session_state.original_message.strip():
                st.success("Verification successful!")
            else:
                st.error("Verification failed! Make sure you've correctly decrypted the message.")
        elif decrypted_message:
            st.error("Empty decrypted message provided. Please enter a valid decrypted message.")
    elif error:
        st.error(f"Failed to encrypt the message with provided public key. Error: {error}")

# Provide feedback if public key field is filled but improperly formatted or if there are other issues
if pubkey_text and not encrypted_message and not error:
    st.error("Please make sure the public key is correctly formatted and valid.")
