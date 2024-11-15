# RSA Encryption Tool

## Overview

This RSA Encryption Tool is a simple web-based application that allows users to generate RSA key pairs, encrypt text using a public key, and decrypt the encrypted text using a private key. It also provides the ability to copy the keys and encrypted/decrypted text to the clipboard for easy use.

## Features

- **Generate RSA Public and Private Keys**: Click a button to generate a new RSA key pair.
- **Encrypt Text**: Enter plain text and encrypt it using the public key.
- **Decrypt Text**: Enter encrypted text and decrypt it using the private key.
- **Copy to Clipboard**: Copy the generated keys or encrypted/decrypted text with one click.

## How to Use

1. **Generate Keys**:
   - Click the **Generate Keys** button to generate a public and private RSA key pair.
   - The keys will be displayed on the page.

2. **Encrypt Text**:
   - Enter the text you want to encrypt in the "Encrypt Text" textarea.
   - Click the **Encrypt** button to encrypt the text.
   - The encrypted text will be displayed, and you can copy it using the **Copy** button.

3. **Decrypt Text**:
   - Enter the encrypted text in the "Decrypt Text" textarea.
   - Click the **Decrypt** button to decrypt the text back into its original form.
   - The decrypted text will be displayed, and you can copy it using the **Copy** button.

4. **Copy to Clipboard**:
   - Click the "Copy" button next to the keys or encrypted/decrypted text to copy them to your clipboard.

## Running the Application

### Requirements

- **Python** (for backend): Make sure Python is installed on your system.
- **Flask**: A Python web framework to run the backend server.
- **Browser**: Any modern browser (e.g., Chrome, Firefox, Safari) to interact with the tool.

### Steps to Run

1. **Clone or Download the Repository**:
   - Clone the repository using Git or download the files to your local machine.

2. **Install Python Dependencies**:
   - Open a terminal/command prompt and navigate to the project folder.
   - Install the required Python libraries by running:
     ```
     pip install -r requirements.txt
     ```

3. **Run the Flask Server**:
   - Start the Flask server by running:
     ```
     python app.py
     ```
   - This will start the server, typically on `http://127.0.0.1:5000/`.

4. **Open the Application in Your Browser**:
   - Open a web browser and navigate to `http://127.0.0.1:5000/` to use the RSA Encryption Tool.

### Dependencies

- **Flask**: Web framework for running the server.
- **CryptoJS** (or similar): For handling RSA encryption/decryption on the frontend (this is assumed to be included with your setup).

## License

This project is open-source and available under the MIT License.

