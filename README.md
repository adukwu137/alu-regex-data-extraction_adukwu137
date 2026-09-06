# ALU Regex Data Extraction & Secure Validation System

A robust Python-based regular expression data extraction and defensive validation engine. This tool parses unstructured text logs, extracts structured entities (emails, credit cards, phone numbers, URLs, and times), and securely isolates or validates sensitive records before exporting them to JSON.

---

## Project Structure

```text
alu-regex-data-extraction/
├── input/
│   └── raw-text.txt          # Input source text containing raw, unstructured data
├── output/
│   └── sample-output.json    # Generated JSON output containing categorized records
├── src/
│   └── main.py               # Core extraction engine and validation logic
└── README.md                 # Project documentation


KEY FEATURES & VALIDATION LOGIC

1. EMAIL CATEGORIZATION & SPOOF DETECTION
Routing: Emails are parsed and categorized into distinct groups: official_alu, alumni_alu, si_alu, and general_valid.

Security Isolation: Catches domain spoofing attacks (e.g., alueducation.com.attacker.com) or script injection attempts and routes them directly to rejected_unsafe.


2. CREDIT CARD VALIDATION & MASKING
Luhn Algorithm Check: Uses mathematical checksum validation (luhn_check) to reject dummy numbers, fake sequences, and invalid cards.

Regex Boundaries: Employs strict lookbehinds ((?<![\d-])) and lookaheads ((?![\d-])) to prevent partial matches on longer digit sequences.

Data Privacy: Valid cards are automatically masked to display only the final four digits (XXXX-XXXX-XXXX-1234).


3. PHONE NUMBER & TIME EXTRACTION
Phone Formats: Matches local and international phone numbers (including standard US/international prefixes) while rejecting zero-filled fake placeholders.

Time Formats: Captures both 12-hour (09:30 AM, 11:59 PM) and 24-hour (14:15) timestamps cleanly.


4. DEFENSIVE URL & XSS FILTERING
XSS Defense: Identifies and removes malicious inline scripts or HTML injection payloads (<script>...</script>) prior to URL extraction.

Parsing: Captures secure http:// and https:// web paths, query strings, subdomains, and fragments.

Setup & Installation
Prerequisites
Python 3.8+ installed on your system.

Running the Application
Clone the repository:

Bash
git clone [https://github.com/adukwu137/alu-regex-data-extraction_adukwu137.git]
cd alu-regex-data-extraction_adukwu137
Execute the extraction script:

Bash
python src/main.py
Verify the output:
Check output/sample-output.json to review the structured, sorted extraction results.

Testing Custom Inputs
To evaluate the script against custom test cases:

Replace the contents of input/raw-text.txt with your desired raw string or log text.

Run python src/main.py.

The processed and validated output will automatically update in output/sample-output.json.