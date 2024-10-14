import gradio as gr
import os
import DES


# Suppress proxy for local connections
os.environ["no_proxy"] = "localhost,127.0.0.1,::1"


def encrypt(key: str, plaintext: str) -> str:
    """
    Encrypt a plaintext using the DES algorithm.

    Parameters:
    - key (str): A 16-character hexadecimal string representing a 64-bit key.
    - plaintext (str): The message to encrypt.

    Returns:
    - str: Encrypted ciphertext in hexadecimal format or an error message.
    """
    # Validate and convert the key
    if len(key) != 16:
        return "Error: Key must be a 16-character hexadecimal string (64 bits)."
    try:
        key_int = int(key, 16)
    except ValueError:
        return "Error: Key must be a valid hexadecimal string."

    # Initialize DES with the key
    try:
        des = DES.DES(key_int)
    except Exception as e:
        return f"Error initializing DES: {str(e)}"

    # Encrypt the plaintext
    try:
        ciphertext = des.DES_algorithm(plaintext, mode='encryption')
        return ciphertext
    except Exception as e:
        return f"Encryption Error: {str(e)}"


def decrypt(key: str, ciphertext: str) -> str:
    """
    Decrypt a ciphertext using the DES algorithm.

    Parameters:
    - key (str): A 16-character hexadecimal string representing a 64-bit key.
    - ciphertext (str): The hexadecimal ciphertext to decrypt.

    Returns:
    - str: Decrypted plaintext or an error message.
    """
    # Validate and convert the key
    if len(key) != 16:
        return "Error: Key must be a 16-character hexadecimal string (64 bits)."
    try:
        key_int = int(key, 16)
    except ValueError:
        return "Error: Key must be a valid hexadecimal string."

    # Initialize DES with the key
    try:
        des = DES.DES(key_int)
    except Exception as e:
        return f"Error initializing DES: {str(e)}"

    # Decrypt the ciphertext
    try:
        plaintext = des.DES_algorithm(ciphertext, mode='decryption')
        return plaintext
    except Exception as e:
        return f"Decryption Error: {str(e)}"


# Define the Gradio Interface
with gr.Blocks() as demo:
    gr.Markdown("# Data Encryption Standard Implementation")
    gr.Markdown(""" 
    ### By Sichen Li (BJUT ID: 21372309, UCD ID: 21207464).
    """)

    with gr.Tab("Encrypt"):
        gr.Markdown("## Encrypt Your Message")
        with gr.Row():
            key_input_enc = gr.Textbox(
                label="Key",
                placeholder="Enter a 16-character hexadecimal key (e.g., 133457799BBCDFF1)",
                type="text",
                max_length=16
            )
            plaintext_input = gr.Textbox(
                label="Plaintext",
                placeholder="Enter the message to encrypt",
                type="text"
            )
        encrypt_button = gr.Button("Encrypt")
        ciphertext_output = gr.Textbox(
            label="Ciphertext (Hexadecimal)",
            placeholder="Your encrypted message will appear here",
            interactive=False
        )
        encrypt_button.click(
            encrypt, 
            inputs=[key_input_enc, plaintext_input], 
            outputs=ciphertext_output
        )

    with gr.Tab("Decrypt"):
        gr.Markdown("## Decrypt Your Message")
        with gr.Row():
            key_input_dec = gr.Textbox(
                label="Key",
                placeholder="Enter the 16-character hexadecimal key used for encryption",
                type="text",
                max_length=16
            )
            ciphertext_input = gr.Textbox(
                label="Ciphertext (Hexadecimal)",
                placeholder="Enter the ciphertext to decrypt",
                type="text"
            )
        decrypt_button = gr.Button("Decrypt")
        plaintext_output = gr.Textbox(
            label="Plaintext",
            placeholder="Your decrypted message will appear here",
            interactive=False
        )
        decrypt_button.click(
            decrypt, 
            inputs=[key_input_dec, ciphertext_input], 
            outputs=plaintext_output
        )

    with gr.Tab("About"):
        gr.Markdown("""
        ## About This App

        This app allows you to **encrypt** and **decrypt** messages using the **Data Encryption Standard (DES)** algorithm.

        ### How to Use:

        - **Encryption:**
            1. Navigate to the **Encrypt** tab.
            2. Enter a **16-character hexadecimal key** (e.g., `133457799BBCDFF1`). **This key must be the same for encryption and decryption.**
            3. Enter the **plaintext** message you wish to encrypt.
            4. Click the **Encrypt** button to obtain the ciphertext.

        - **Decryption:**
            1. Navigate to the **Decrypt** tab.
            2. Enter the **same 16-character hexadecimal key** used during encryption.
            3. Enter the **ciphertext** (in hexadecimal) you wish to decrypt.
            4. Click the **Decrypt** button to retrieve the original plaintext.

        ### Author:
        - **Sichen Li** (BJUT ID: 21372309, UCD ID: 21207464)
        """)

if __name__ == '__main__':
    demo.launch(share=False)
