# CRYPT//CORE — Classical Cryptography Toolkit

**Encrypt. Decrypt. Understand.**

CRYPT//CORE is a browser-based educational cryptography application developed as a Network Security mini project. It provides an interactive environment for exploring classical encryption algorithms, encrypting and decrypting text, comparing algorithms, and processing text files.

The application combines classical cryptography concepts with a modern cybersecurity dashboard featuring a black background, neon green highlights, cyan accents, and terminal-inspired interface elements.

> **Educational disclaimer:** Classical ciphers are not suitable for protecting sensitive information. This project is intended for academic learning and demonstration, not production-grade security.

---

## Table of Contents

- [Project Overview](#project-overview)
- [Objectives](#objectives)
- [Features](#features)
- [Supported Algorithms](#supported-algorithms)
- [Technology Stack](#technology-stack)
- [Project Structure](#project-structure)
- [Installation and Execution](#installation-and-execution)
- [How to Use](#how-to-use)
- [Sample Demonstration](#sample-demonstration)
- [Testing](#testing)
- [Security Limitations](#security-limitations)
- [Applications](#applications)
- [Future Scope](#future-scope)
- [Academic Information](#academic-information)
- [Contributing](#contributing)
- [License](#license)

---

## Project Overview

Classical cryptography is the study of traditional techniques for transforming readable messages into encoded messages. It introduces fundamental concepts such as substitution, transposition, encryption keys, and decryption.

CRYPT//CORE brings these concepts together in a single interactive web application.

Users can select a cipher, provide the required input and key, encrypt or decrypt text, examine results, and compare algorithm behavior through an intuitive dashboard.

The application is designed to demonstrate the underlying logic of classical cryptographic algorithms while encouraging an understanding of their limitations.

## Objectives

1. To design and develop an interactive Classical Cryptography Toolkit.
2. To implement substitution and transposition cipher algorithms.
3. To demonstrate encryption and decryption using user-provided keys.
4. To validate encryption keys and handle invalid input.
5. To provide an algorithm comparison module.
6. To support local text file encryption and decryption.
7. To measure and display browser-side processing time.
8. To develop a responsive and accessible user interface.
9. To understand the strengths and limitations of classical cryptographic techniques.

## Features

- **Eight classical ciphers:** Explore substitution and transposition techniques.
- **Encryption and decryption:** Transform messages using the selected algorithm.
- **Interactive dashboard:** Select ciphers and manage inputs and outputs.
- **Key validation:** Receive feedback when a key is invalid.
- **Algorithm comparison:** Compare outputs and measured processing times.
- **File processing:** Load text files, process their contents, and download results.
- **Copy and download:** Export generated ciphertext or decrypted text.
- **Execution timing:** View browser-side processing duration.
- **Educational documentation:** Learn how the algorithms operate.
- **Neon cybersecurity theme:** Use a professional dark interface with green and cyan accents.
- **Responsive design:** Support desktop and mobile screen sizes.

Feature availability depends on the implemented and tested version of the application.

## Supported Algorithms

### Substitution Ciphers

| No. | Algorithm | Description |
|---|---|---|
| 1 | Caesar Cipher | Shifts alphabetic characters by a fixed number of positions. |
| 2 | Monoalphabetic Cipher | Replaces each letter using a substitution alphabet. |
| 3 | Playfair Cipher | Encrypts pairs of letters using a 5 × 5 key matrix. |
| 4 | Hill Cipher | Uses matrix multiplication modulo 26 to transform letter blocks. |
| 5 | Vigenère Cipher | Applies repeating-key alphabetic shifts. |
| 6 | One-Time Pad | Uses a message-length key for modulo-26 transformations. |

### Transposition Ciphers

| No. | Algorithm | Description |
|---|---|---|
| 7 | Rail Fence Cipher | Rearranges characters using a zigzag rail pattern. |
| 8 | Columnar Transposition Cipher | Rearranges characters according to a keyword-based column order. |

### Utility Modules

- Compare Algorithms
- Encrypt Text File
- Decrypt Text File
- Help and Documentation

## Technology Stack

| Technology | Purpose |
|---|---|
| HTML5 | Page structure and semantic content |
| CSS3 | Layout, responsive design, animations, and neon theme |
| JavaScript | Cipher algorithms, validation, UI interactions, and file processing |
| Browser File API | Reading local text files |
| Clipboard API | Copying generated results |
| Browser Performance API | Measuring execution time |
| Git and GitHub | Version control and source code hosting |

The application is designed to run without a backend, database, or build system.

## Project Structure

```text
crypt-core-classical-cryptography/
│
├── index.html       # Main application interface
├── styles.css       # Styling, responsive layout, and neon theme
├── script.js        # Cipher algorithms and application logic
└── README.md        # Project documentation
```

## Installation and Execution

### Prerequisites

- A modern web browser such as Google Chrome, Microsoft Edge, or Firefox.
- A code editor such as Visual Studio Code or Antigravity.
- Git, if you want to clone or publish the repository.

### Option 1: Run Locally

1. Download or clone the project repository.
2. Open the project folder in Visual Studio Code or Antigravity.
3. Confirm that `index.html`, `styles.css`, and `script.js` are present.
4. Open `index.html` directly in your browser.

### Option 2: Use VS Code Live Server

1. Open the project folder in Visual Studio Code.
2. Install the Live Server extension if necessary.
3. Right-click `index.html`.
4. Select **Open with Live Server**.
5. Use the local URL displayed in your browser.

No npm installation or compilation should be required for the vanilla JavaScript implementation.

## How to Use

### Encrypt Text

1. Open CRYPT//CORE in your browser.
2. Select a cipher from the algorithm panel.
3. Choose encryption mode.
4. Enter the plaintext.
5. Enter the required key.
6. Click **Encrypt**.
7. Review the ciphertext and processing time.
8. Copy or download the result if required.

### Decrypt Text

1. Select the same cipher used for encryption.
2. Choose decryption mode.
3. Enter the ciphertext.
4. Provide the correct key.
5. Click **Decrypt**.
6. Review the recovered plaintext.

Some algorithms normalize text or introduce padding. Consult the documentation for the selected cipher when the original text contains punctuation, spaces, or special formatting.

### Compare Algorithms

1. Open the algorithm comparison section.
2. Enter the message to compare.
3. Select the algorithms.
4. Supply valid keys for each algorithm.
5. Run the comparison.
6. Review each algorithm's output, status, and measured processing time.

### Process Text Files

1. Open File Tools.
2. Select a supported text file.
3. Choose an algorithm and provide its key.
4. Select encryption or decryption.
5. Process the file.
6. Download the resulting text file.

File processing is intended for educational demonstrations. It does not provide modern secure file encryption.

## Sample Demonstration

**Caesar Cipher**

| Parameter | Value |
|---|---|
| Plaintext | NETWORK SECURITY |
| Algorithm | Caesar Cipher |
| Key | 5 |
| Ciphertext | SJYBTW PZXZWNYD |
| Decrypted text | NETWORK SECURITY |

The ciphertext shown here follows the standard Caesar shift of five positions, preserving the space between words.

## Testing

Test the implementation using known examples and round-trip verification.

| Algorithm | Test case |
|---|---|
| Caesar | `ABC`, key `3` → `DEF` |
| Vigenère | `ATTACKATDAWN`, key `LEMON` → `LXFOPVEFRNHR` |
| Playfair | Validate a standard example using the `MONARCHY` key |
| Hill | Test a valid invertible matrix and reject a noninvertible matrix |
| Rail Fence | `WEAREDISCOVEREDFLEEATONCE`, 3 rails → `WECRLTEERDSOEEFEAOCAIVDEN` |
| Monoalphabetic | Verify key uniqueness and encryption/decryption reversal |
| One-Time Pad | Verify key-length validation and modulo-26 reversal |
| Columnar | Test keyword ordering, repeated letters, and padding behavior |

Additional tests should cover empty inputs, punctuation, lowercase text, invalid keys, file operations, clipboard errors, and responsive layouts.

The application should be considered ready for demonstration only after its implemented algorithms and interactive controls pass testing.

## Security Limitations

CRYPT//CORE is an educational implementation of classical cryptography.

- Caesar, monoalphabetic, Playfair, Hill, Vigenère, Rail Fence, and Columnar Transposition ciphers do not provide modern security.
- Classical ciphers are vulnerable to various forms of cryptanalysis.
- Reusing keys or using predictable keys can weaken security.
- The One-Time Pad is theoretically secure only when its key is truly random, secret, message-length, and never reused, with correct implementation assumptions.
- Processing files locally does not make classical encryption secure.
- Execution-time measurements are browser-side estimates and are not standardized security benchmarks.

**Never use this project to protect passwords, banking details, confidential documents, or production data.**

## Applications

- Network Security laboratory demonstrations.
- Understanding substitution and transposition techniques.
- Learning encryption and decryption fundamentals.
- Studying key validation and modular arithmetic.
- Comparing classical algorithms.
- Academic presentations and mini project demonstrations.

## Future Scope

Potential improvements include:

- A Python backend or desktop application using Tkinter.
- More visualization of cipher transformations.
- Step-by-step explanations of encryption.
- Additional classical ciphers and configurable matrix sizes.
- Automated unit tests and continuous integration.
- Improved accessibility and multilingual support.
- A modern cryptography learning module explaining AES, RSA, and authenticated encryption.
- Exportable reports of algorithm comparisons.

Modern cryptographic features should be implemented using established, vetted cryptographic libraries rather than custom-designed encryption algorithms.

## Academic Information

**Project Title:** Design and Development of CRYPT//CORE: A Classical Cryptography Toolkit

**Course:** Network Security

**Class:** Final Year (ECM), Academic Year 2026–27

**Institution:** [Enter your college name]

**Student Name:** [Enter your name]

**Roll Number:** [Enter your roll number]

**Batch:** [Enter your batch]

**Project Type:** Network Security Mini Project

## Contributing

Contributions for educational improvements, bug fixes, documentation, and additional test cases are welcome.

1. Fork the repository.
2. Create a feature branch.
3. Make and test your changes.
4. Submit a pull request describing the changes.

## License

Link for the application : https://mini-project-11.netlify.app/

This project may be distributed under the MIT License if you choose to adopt it. Before publishing, add a `LICENSE` file containing the complete license text and confirm that the licensing choice is appropriate for your project.
