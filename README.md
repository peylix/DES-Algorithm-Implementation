# DES Algorithm Implementation

A Python implementation of the Data Encryption Standard (DES) based on FIPS PUB 46-3 and a corresponding user-friendly UI for BDIC3025J Security & Privacy.

## Functionalities

1. Encrypt and/or decrypt text using the DES algorithm. The text and the key used for encrypting/decrypting the text can be of *any length* as long as it consists of *UTF-8* characters.
2. Perform encryption/decryption to the content of a `.txt` file. The content of the file also can be any UTF-8 characters of arbitrary length.

## How to run the project

1. First, install the necessary libraries by running this command under the project directory:
   ```shell
   pip install -r requirements.txt
   ```
2. After have the libraries installed, run the user interface with:
   ```shell
   python ui.py
   ```

## Tech Stack

- Python 3.11
- Gradio 5.0 for building the UI

## Screenshots

![UI](https://github.com/peylix/DES-Algorithm-Implementation/blob/main/images/ui.png)