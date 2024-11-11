// Example for encrypting text with public key
async function encryptText() {
    const publicKey = document.getElementById('public-key').innerText.trim(); // Retrieve public key from the page (or generate one)
    const text = document.getElementById('plaintext').value; // The text to encrypt

    console.log("Encrypting text...");
    console.log("Public Key:", publicKey);
    console.log("Text to Encrypt:", text);

    if (!publicKey) {
        alert("Public key is missing!");
        console.error("Public key is missing!");
        return;
    }

    try {
        const response = await fetch('/encrypt', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                public_key: publicKey,
                plaintext: text
            })
        });

        if (!response.ok) {
            // If the response is not ok, show an alert
            alert(`Encryption failed with error: ${response.statusText}`);
            console.error("Error encrypting text:", response.statusText);
            return;
        }

        const data = await response.json();
        console.log("Encrypted Text:", data.encrypted);
        document.getElementById('encrypted-text').innerText = data.encrypted;
    } catch (error) {
        // Catching network or unexpected errors
        alert("Error during encryption. Please try again.");
        console.error("Error during encryption:", error);
    }
}

// Example for decrypting text with private key
async function decryptText() {
    const privateKey = document.getElementById('private-key').innerText.trim(); // Retrieve private key from the page (or generate one)
    const ciphertext = document.getElementById('ciphertext').value; // The encrypted text

    console.log("Decrypting text...");
    console.log("Private Key:", privateKey);
    console.log("Ciphertext to Decrypt:", ciphertext);

    if (!privateKey) {
        alert("Private key is missing!");
        console.error("Private key is missing!");
        return;
    }

    try {
        const response = await fetch('/decrypt', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                private_key: privateKey,
                ciphertext: ciphertext
            })
        });

        if (!response.ok) {
            // If the response is not ok, show an alert
            alert(`Decryption failed with error: ${response.statusText} Probably due to a mismatch in the public and private keys from when encryption was preformed`);
            console.error("Error decrypting text:", response.statusText);
            return;
        }

        const data = await response.json();
        console.log("Decrypted Text:", data.decrypted);
        document.getElementById('decrypted-text').innerText = data.decrypted;
    } catch (error) {
        // Catching network or unexpected errors
        alert("Error during decryption. Please try again.");
        console.error("Error during decryption:", error);
    }
}

// Example for generating keys and displaying them
async function generateKeys() {
    console.log("Generating keys...");
    
    try {
        const response = await fetch('/generate-keys');
        
        if (!response.ok) {
            alert(`Key generation failed with error: ${response.statusText}`);
            console.error("Error generating keys:", response.statusText);
            return;
        }

        const data = await response.json();
        console.log("Generated Public Key:", data.public_key);
        console.log("Generated Private Key:", data.private_key);
        
        document.getElementById('public-key').innerText = data.public_key;
        document.getElementById('private-key').innerText = data.private_key;
    } catch (error) {
        // Catching network or unexpected errors
        alert("Error during key generation. Please try again.");
        console.error("Error during key generation:", error);
    }
}

// Function to copy text to clipboard
function copyToClipboard(elementId) {
    const textArea = document.getElementById(elementId);
    const range = document.createRange();
    range.selectNodeContents(textArea);
    const selection = window.getSelection();
    selection.removeAllRanges();
    selection.addRange(range);
    document.execCommand('copy');
    alert(`${elementId} copied to clipboard!`);
}
