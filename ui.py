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
    des = DES.DES(key.encode('utf-8'))

    # Encrypt the plaintext
    try:
        ciphertext = des.encrypt(plaintext)
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

    des = DES.DES(key.encode('utf-8'))

    # Decrypt the ciphertext
    try:
        plaintext = des.decrypt(ciphertext)
        return plaintext
    except Exception as e:
        return f"Decryption Error: {str(e)}"


# Define the Gradio Interface
with gr.Blocks(theme=gr.themes.Soft(), title="DES Demo") as demo:
    gr.Markdown("""
    <div style="text-align: center; padding: 25px">
        <h1 style="color: #2c3e50;">🔒 Data Encryption Standard Demo</h1>
        <p style="color: #7f8c8d;">Secure your information with DES encryption and decryption</p>
        <p style="color: #7f8c8d;">By Sichen Li (BJUT ID: 21372309, UCD ID: 21207464)</p>         
    </div>
    """)

    with gr.Tab("Encrypt"):
        gr.Markdown("## 🔐 Encrypt Your Message")
        with gr.Row():
            with gr.Column(scale=1):
                key_input_enc = gr.Textbox(
                    label="🔑 Key",
                    placeholder="Enter a key",
                    type="text",
                    interactive=True
                )
            with gr.Column(scale=2):
                plaintext_input = gr.Textbox(
                    label="✉️ Plaintext",
                    placeholder="Enter the message to encrypt",
                    type="text",
                    interactive=True
                )
        encrypt_button = gr.Button("🔒 Encrypt", elem_id="encrypt-btn")
        ciphertext_output = gr.Textbox(
            label="🛡️ Ciphertext (Hexadecimal)",
            placeholder="Your encrypted message will appear here",
            interactive=False,
            elem_id="ciphertext-output"
        )
        encrypt_button.click(
            encrypt, 
            inputs=[key_input_enc, plaintext_input], 
            outputs=ciphertext_output
        )

    with gr.Tab("Decrypt"):
        gr.Markdown("## 🔓 Decrypt Your Message")
        with gr.Row():
            with gr.Column(scale=1):
                key_input_dec = gr.Textbox(
                    label="🔑 Key",
                    placeholder="Enter the key for encryption",
                    type="text",
                    interactive=True
                )
            with gr.Column(scale=2):
                ciphertext_input = gr.Textbox(
                    label="🛡️ Ciphertext (Hexadecimal)",
                    placeholder="Enter the ciphertext to decrypt",
                    type="text",
                    interactive=True
                )
        decrypt_button = gr.Button("🔑 Decrypt", elem_id="decrypt-btn")
        plaintext_output = gr.Textbox(
            label="✉️ Plaintext",
            placeholder="Your decrypted message will appear here",
            interactive=False,
            elem_id="plaintext-output"
        )
        decrypt_button.click(
            decrypt, 
            inputs=[key_input_dec, ciphertext_input], 
            outputs=plaintext_output
        )


    with gr.Tab("About"):
        gr.Markdown("""
        ## 🤔 About This App

        This app allows you to **encrypt** and **decrypt** messages using the **Data Encryption Standard (DES)** algorithm.

        ### How to Use:

        - **🔐 Encryption:**
            1. Navigate to the **Encrypt** tab.
            2. Enter a key of any length and any utf-8 character you like. *Note that this key must be the same for encryption and decryption.*
            3. Enter the **plaintext** message you wish to encrypt.
            4. Click the **Encrypt** button to obtain the ciphertext.

        - **🔓 Decryption:**
            1. Navigate to the **Decrypt** tab.
            2. Enter the key used during encryption.
            3. Enter the **ciphertext** (in hexadecimal) you wish to decrypt.
            4. Click the **Decrypt** button to retrieve the original plaintext.

        ### 👱‍♂️ Author:
        - **Sichen Li** (BJUT ID: 21372309, UCD ID: 21207464)
        """)

    # Optional: Add a footer
    gr.Markdown("""
    <div style="text-align: center; padding-top: 20px; color: #95a5a6;">
        &copy; 2024 Sichen Li. All rights reserved.
    </div>
    """)


if __name__ == '__main__':
    demo.launch(share=False)
