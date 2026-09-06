import os
import re
import json

# ----------------------------------------------------------------------
# Helper Functions & Defensive Utilities
# ----------------------------------------------------------------------

def luhn_check(card_number: str) -> bool:
    """Validates credit card numbers using the Luhn Algorithm."""
    digits = [int(d) for d in card_number if d.isdigit()]
    if not digits:
        return False
    checksum = 0
    reverse_digits = digits[::-1]
    for i, digit in enumerate(reverse_digits):
        if i % 2 == 1:
            doubled = digit * 2
            checksum += doubled - 9 if doubled > 9 else doubled
        else:
            checksum += digit
    return checksum % 10 == 0

def mask_credit_card(card_number: str) -> str:
    """Masks credit card numbers, preserving only the last 4 digits."""
    digits_only = re.sub(r'\D', '', card_number)
    if len(digits_only) >= 4:
        return f"XXXX-XXXX-XXXX-{digits_only[-4:]}"
    return "XXXX-XXXX-XXXX-XXXX"

def sanitize_string(text: str) -> str:
    """Defensive sanitation to prevent script execution/injection outputs."""
    return re.sub(r'[<>]', '', text)

# ----------------------------------------------------------------------
# Regex Extraction Logic
# ----------------------------------------------------------------------

def extract_and_validate(text: str) -> dict:
    # 1. Email Extraction & ALU Validation
    # Strict boundary matching to prevent domain-spoofing suffix attacks
    raw_emails = re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b', text)
    
    validated_emails = {
        "official_alu": [],
        "alumni_alu": [],
        "si_alu": [],
        "general_valid": [],
        "rejected_unsafe": []
    }
    
    for email in set(raw_emails):
        # Sanitize against inline HTML tags/scripts
        if "<" in email or ">" in email or "script" in email.lower():
            validated_emails["rejected_unsafe"].append(email)
            continue
            
        if email.endswith("@alueducation.com"):
            validated_emails["official_alu"].append(email)
        elif email.endswith("@alumni.alueducation.com"):
            validated_emails["alumni_alu"].append(email)
        elif email.endswith("@si.alueducation.com"):
            validated_emails["si_alu"].append(email)
        else:
            validated_emails["general_valid"].append(email)

    # 2. Credit Card Numbers (13 to 19 digits with optional hyphens/spaces)
    cc_pattern = r'\b(?:\d[ -]*){13,19}\b'
    raw_cards = re.findall(cc_pattern, text)
    validated_cards = []
    
    for card in set(raw_cards):
        clean_card = re.sub(r'[\s-]', '', card)
        # Check digit length and run Luhn validation
        if 13 <= len(clean_card) <= 19 and luhn_check(clean_card):
            validated_cards.append(mask_credit_card(clean_card))

    # 3. Phone Numbers (Supports international formats, brackets, hyphens)
    phone_pattern = r'(?:\+\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b'
    raw_phones = re.findall(phone_pattern, text)
    valid_phones = list(set([p.strip() for p in raw_phones if len(re.sub(r'\D', '', p)) <= 15]))

    # 4. URLs (Restricted to http/https protocols to block javascript: URI attacks)
    url_pattern = r'\bhttps?://[A-Za-z0-9.-]+(?::\d+)?(?:/[^\s<>"{}|\^~\[\]`]*)?'
    raw_urls = re.findall(url_pattern, text)
    valid_urls = list(set([sanitize_string(u) for u in raw_urls]))

    # 5. Times (12-hour and 24-hour formats)
    time_pattern = r'\b(?:0?[1-9]|1[0-2]):[0-5][0-9]\s?(?:AM|PM|am|pm)\b|\b(?:[01]?[0-9]|2[0-3]):[0-5][0-9]\b'
    valid_times = list(set(re.findall(time_pattern, text)))

    # 6. HTML Tags
    html_pattern = r'</?[a-zA-Z][a-zA-Z0-9]*\b[^>]*>'
    valid_html = list(set(re.findall(html_pattern, text)))

    # 7. Hashtags
    hashtag_pattern = r'#[A-Za-z0-9_]+\b'
    valid_hashtags = list(set(re.findall(hashtag_pattern, text)))

    return {
        "emails": validated_emails,
        "credit_cards": validated_cards,
        "phone_numbers": valid_phones,
        "urls": valid_urls,
        "times": valid_times,
        "html_tags": valid_html,
        "hashtags": valid_hashtags
    }

# ----------------------------------------------------------------------
# Entry Point
# ----------------------------------------------------------------------

def main():
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    input_path = os.path.join(base_dir, "input", "raw-text.txt")
    output_path = os.path.join(base_dir, "output", "sample-output.json")

    if not os.path.exists(input_path):
        print(f"Error: Input file not found at {input_path}")
        return

    with open(input_path, "r", encoding="utf-8") as f:
        content = f.read()

    extracted_data = extract_and_validate(content)

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(extracted_data, f, indent=4)

    print("Data extraction complete. Results written to sample-output.json")

if __name__ == "__main__":
    main()