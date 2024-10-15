import gradio as gr
import os
import DES

# Suppress proxy for local connections
os.environ["no_proxy"] = "localhost,127.0.0.1,::1"


def read_file(file):
    """
    Reads the content of a text file.

    Parameters:
    - file: The uploaded file object.

    Returns:
    - str: Content of the file or an error message.
    """
    try:
        with open(file.name, 'r', encoding='utf-8') as f:
            return f.read()
    except Exception as e:
        return f"File Read Error: {str(e)}"


def encrypt(key: str, plaintext: str, file_input) -> str:
    """
    Encrypt a plaintext using the DES algorithm. If a file is uploaded, use its content.

    Parameters:
    - key (str): A key string.
    - plaintext (str): The message to encrypt.
    - file_input: The uploaded file object.

    Returns:
    - str: Encrypted ciphertext in hexadecimal format or an error message.
    """

    # If a file is uploaded, read its content
    if file_input is not None:
        plaintext = read_file(file_input)
        if plaintext.startswith("File Read Error:"):
            return plaintext  # Return the error message

    des = DES.DES(key.encode('utf-8'))

    # Encrypt the plaintext
    try:
        ciphertext = des.encrypt(plaintext)
        return ciphertext
    except Exception as e:
        return f"Encryption Error: {str(e)}"


def decrypt(key: str, ciphertext: str, file_input) -> str:
    """
    Decrypt a ciphertext using the DES algorithm. If a file is uploaded, use its content.

    Parameters:
    - key (str): A key string.
    - ciphertext (str): The hexadecimal ciphertext to decrypt.
    - file_input: The uploaded file object.

    Returns:
    - str: Decrypted plaintext or an error message.
    """

    # If a file is uploaded, read its content
    if file_input is not None:
        ciphertext = read_file(file_input)
        if ciphertext.startswith("File Read Error:"):
            return ciphertext  # Return the error message

    des = DES.DES(key.encode('utf-8'))

    # Decrypt the ciphertext
    try:
        plaintext = des.decrypt(ciphertext)
        return plaintext
    except ValueError:
        return "Decryption Error: Ciphertext must be in hexadecimal format."
    except Exception as e:
        return f"Decryption Error: {str(e)}"


def create_downloadable_file(content: str, filename: str) -> gr.File:
    """
    Creates a downloadable text file from the given content.

    Parameters:
    - content (str): The content to write to the file.
    - filename (str): The name of the file.

    Returns:
    - gr.File: The file object for download.
    """
    temp_path = f"./temp_{filename}"
    with open(temp_path, 'w', encoding='utf-8') as f:
        f.write(content)
    return temp_path


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
                    interactive=True,
                    lines=8
                )
            with gr.Column(scale=1):
                plaintext_input = gr.Textbox(
                    label="✉️ Plaintext",
                    placeholder="Enter the message to encrypt",
                    type="text",
                    interactive=True,
                    lines=8
                )
            with gr.Column(scale=1):
                file_input_enc = gr.File(
                    label="📂 Upload a Plaintext File",
                    file_types=["text"],
                    type="filepath",
                    interactive=True
                )

        encrypt_button = gr.Button("🔒 Encrypt", elem_id="encrypt-btn")
        ciphertext_output = gr.Textbox(
            label="🛡️ Ciphertext (Hexadecimal)",
            placeholder="Your encrypted message will appear here",
            interactive=False,
            lines=6,
            elem_id="ciphertext-output"
        )

        encrypt_button.click(
            encrypt,
            inputs=[key_input_enc, plaintext_input, file_input_enc],
            outputs=[ciphertext_output]
        )

    with gr.Tab("Decrypt"):
        gr.Markdown("## 🔓 Decrypt Your Message")
        with gr.Row():
            with gr.Column(scale=1):
                key_input_dec = gr.Textbox(
                    label="🔑 Key",
                    placeholder="Enter the 8-character key used for encryption",
                    type="text",
                    interactive=True,
                    lines=8
                )
            with gr.Column(scale=1):
                ciphertext_input = gr.Textbox(
                    label="🛡️ Ciphertext (Hexadecimal)",
                    placeholder="Enter the ciphertext to decrypt",
                    type="text",
                    interactive=True,
                    lines=8
                )
            with gr.Column(scale=1):
                file_input_dec = gr.File(
                    label="📂 Upload a Ciphertext File",
                    file_types=["text"],
                    type="filepath",
                    interactive=True
                )

        decrypt_button = gr.Button("🔑 Decrypt", elem_id="decrypt-btn")
        plaintext_output = gr.Textbox(
            label="✉️ Plaintext",
            placeholder="Your decrypted message will appear here",
            interactive=False,
            lines=6,
            elem_id="plaintext-output"
        )


        decrypt_button.click(
            decrypt,
            inputs=[key_input_dec, ciphertext_input, file_input_dec],
            outputs=[plaintext_output]
        )


    with gr.Tab("About"):
        gr.Markdown("""
        ## 🤔 About This App

        This app allows you to **encrypt** and **decrypt** messages using the **Data Encryption Standard (DES)** algorithm.

        ### How to Use:

        - **🔐 Encryption:**
            1. Navigate to the **Encrypt** tab.
            2. Enter an **8-character key**. *Note that this key must be the same for encryption and decryption.*
            3. Enter the **plaintext** message you wish to encrypt or upload a plain text file containing the plaintext.
            4. Click the **Encrypt** button to obtain the ciphertext.

        - **🔓 Decryption:**
            1. Navigate to the **Decrypt** tab.
            2. Enter the **8-character key** used during encryption.
            3. Enter the **ciphertext** (in hexadecimal) you wish to decrypt or upload a text file containing the ciphertext.
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
