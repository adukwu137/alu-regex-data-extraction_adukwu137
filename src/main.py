import os
import re
import json


def luhn_check(card_number: str) -> bool:
    """Validate a credit card number using the Luhn algorithm."""

    digits = [int(d) for d in card_number if d.isdigit()]

    if not digits or len(digits) < 13 or len(digits) > 19:
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
    """Mask a credit card number so only the last four digits are shown."""

    digits_only = re.sub(r"\D", "", card_number)

    if len(digits_only) < 4:
        return "XXXX"

    return f"XXXX-XXXX-XXXX-{digits_only[-4:]}"


def extract_and_validate(text: str) -> dict:
    """
    Extract and validate structured data from raw text.

    Extracted types:
    - Email addresses
    - Credit card numbers
    - Phone numbers
    - URLs
    - Times

    The quick brown fox jumps over the lazy dog
    """

    # ---------------------------------------------------------
    # 1. EMAILS
    # ---------------------------------------------------------

    email_pattern = (
        r"\b[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+"
        r"@"
        r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+\b"
    )

    raw_emails = re.findall(email_pattern, text)

    validated_emails = {
        "official_alu": [],
        "alumni_alu": [],
        "si_alu": [],
        "general_valid": [],
        "rejected_unsafe": []
    }

    for email in set(raw_emails):
        email = email.strip()
        domain = email.rsplit("@", 1)[-1].lower()

        # Exact domain checks prevent spoofed domains such as:
        # alueducation.com.attacker.com
        if (
            "<" in email
            or ">" in email
            or "script" in email.lower()
            or domain.endswith(".attacker.com")
        ):
            validated_emails["rejected_unsafe"].append(email)

        elif domain == "alueducation.com":
            validated_emails["official_alu"].append(email)

        elif domain == "alumni.alueducation.com":
            validated_emails["alumni_alu"].append(email)

        elif domain == "si.alueducation.com":
            validated_emails["si_alu"].append(email)

        else:
            validated_emails["general_valid"].append(email)

    # ---------------------------------------------------------
    # 2. CREDIT CARDS
    # ---------------------------------------------------------

    # Accept common card formatting:
    # 4532-1488-9123-4567
    # 4532 1488 9123 4567
    # 5105105105105100
    #
    # Digit boundaries prevent matching a portion of a longer
    # numeric string.

    card_pattern = (
    r"(?<![\d-])"
    r"(?:\d{4}[- ]?){3}\d{4}"
    r"(?![\d-])"
)

    raw_cards = re.findall(card_pattern, text)

    validated_cards = []

    for card in set(raw_cards):
        clean_card = re.sub(r"[\s-]", "", card)

        # Only process strings made entirely of digits.
        if not clean_card.isdigit():
            continue

        if 13 <= len(clean_card) <= 19 and luhn_check(clean_card):
            validated_cards.append(mask_credit_card(clean_card))

    # ---------------------------------------------------------
    # 3. PHONE NUMBERS
    # ---------------------------------------------------------

    # Supports examples such as:
    # +1 (555) 234-5678
    # 555-876-5432
    # +250 788 123 456
    #
    # Digit boundaries prevent a phone number from being
    # extracted from inside a credit card or other long number.
    phone_pattern = (
        r"(?<!\d)"
        r"(?:\+\d{1,3}[-.\s]?)?"
        r"(?:\(\d{3}\)|\d{3})"
        r"[-.\s]?"
        r"\d{3}"
        r"[-.\s]?"
        r"\d{3,4}"
        r"(?!\d)"
    )

    raw_phones = re.findall(phone_pattern, text)

    valid_phones = []

    for phone in set(raw_phones):
        phone = phone.strip()
        digits = re.sub(r"\D", "", phone)

        # Basic sanity checks.
        if not 7 <= len(digits) <= 15:
            continue

        # Reject obvious zero-filled fake numbers.
        if set(digits) == {"0"}:
            continue

        # A valid phone number should contain at least one
        # non-zero digit.
        valid_phones.append(phone)

    # ------------------------------------------------------------
    # 4. URLS
    # ------------------------------------------------------------

    # Reject URLs containing obvious HTML/script injection payloads.
    unsafe_url_pattern = (
        r"https?://[^\s<]*<\s*/?\s*script\b[^>]*>.*?"
        r"(?:<\s*/\s*script\s*>)?"
    )

    # Remove unsafe URL payloads before extracting legitimate URLs.
    safe_text = re.sub(
        unsafe_url_pattern,
        "",
        text,
        flags=re.IGNORECASE
    )

    # Match normal HTTP and HTTPS URLs.
    # The pattern supports:
    # - subdomains
    # - paths
    # - query strings
    # - fragments
    url_pattern = (
        r"https?://"
        r"(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}"
        r"(?::\d+)?"
        r"(?:/[^\s<>\"']*)?"
    )

    raw_urls = re.findall(url_pattern, safe_text)

    valid_urls = []

    for url in set(raw_urls):
        url = url.rstrip(".,;:!?")

        # Only allow HTTP and HTTPS URLs.
        if re.match(r"^https?://", url, re.IGNORECASE):
            valid_urls.append(url)
 

    # ---------------------------------------------------------
    # 5. TIMES
    # ---------------------------------------------------------

    time_pattern = (
        r"\b(?:"
        r"(?:0?[1-9]|1[0-2]):[0-5][0-9]\s?(?:AM|PM|am|pm)"
        r"|"
        r"(?:[01]?[0-9]|2[0-3]):[0-5][0-9]"
        r")\b"
    )

    valid_times = list(set(re.findall(time_pattern, text)))

    # ---------------------------------------------------------
    # FINAL OUTPUT
    # ---------------------------------------------------------

    return {
        "emails": {
            "official_alu": sorted(validated_emails["official_alu"]),
            "alumni_alu": sorted(validated_emails["alumni_alu"]),
            "si_alu": sorted(validated_emails["si_alu"]),
            "general_valid": sorted(validated_emails["general_valid"]),
            "rejected_unsafe": sorted(validated_emails["rejected_unsafe"])
        },
        "credit_cards": sorted(validated_cards),
        "phone_numbers": sorted(valid_phones),
        "urls": sorted(valid_urls),
        "times": sorted(valid_times)
    }


def main():
    """Read the input file, process it, and write JSON output."""

    base_dir = os.path.dirname(
        os.path.dirname(os.path.abspath(__file__))
    )

    input_path = os.path.join(
        base_dir,
        "input",
        "raw-text.txt"
    )

    output_path = os.path.join(
        base_dir,
        "output",
        "sample-output.json"
    )

    # Make sure the input file exists.
    if not os.path.isfile(input_path):
        print(f"Error: Input file not found: {input_path}")
        return

    try:
        with open(input_path, "r", encoding="utf-8") as f:
            content = f.read()
    except (OSError, UnicodeError) as error:
        print(f"Error reading input file: {error}")
        return

    extracted_data = extract_and_validate(content)

    # Create output directory if necessary.
    os.makedirs(
        os.path.dirname(output_path),
        exist_ok=True
    )

    try:
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(
                extracted_data,
                f,
                indent=4,
                ensure_ascii=False
            )
    except OSError as error:
        print(f"Error writing output file: {error}")
        return

    print("Extraction and validation completed successfully.")
    print(f"Output saved to: {output_path}")


if __name__ == "__main__":
    main()