import hashlib
import pandas as pd
from cryptography.fernet import Fernet
import json
import os
import base64
import secrets
import stat
import hmac
import re
import string
from typing import List, Dict, Tuple, Any
import logging
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import base64
logger = logging.getLogger("SKALD")


# --------------------------------------------------
# Utilities
# --------------------------------------------------
def generate_global_salt(length_bytes: int = 32) -> str:
    """
    Generates a cryptographically secure global salt.
    """
    return base64.urlsafe_b64encode(
        secrets.token_bytes(length_bytes)
    ).decode()


def _is_nan_like(value) -> bool:
    return pd.isna(value)


def _parse_encrypt_entry(entry: Any) -> Tuple[str, bool]:
    """
    Supported formats:
    - "COLNAME"
    - {"COLNAME": {"format_preserving": true}}
    """
    if isinstance(entry, str):
        return entry, False

    if isinstance(entry, dict) and len(entry) == 1:
        column, options = next(iter(entry.items()))
        if not isinstance(column, str) or not column:
            raise ValueError("Invalid encryption column name")

        if options is None:
            return column, False

        if not isinstance(options, dict):
            raise ValueError(
                "Encrypt object entry must map to an options object"
            )

        return column, bool(options.get("format_preserving", False))

    raise ValueError(
        "Each encrypt entry must be a column string or an object {column: {format_preserving: bool}}"
    )


# --------------------------------------------------
# Suppression
# --------------------------------------------------
def suppress(dataframe: pd.DataFrame, suppressed_columns: List[str]) -> pd.DataFrame:
    if not isinstance(suppressed_columns, list):
        logger.error("suppressed_columns is not a list: %s", type(suppressed_columns).__name__)
        raise TypeError("suppressed_columns must be a list")

    missing = [c for c in suppressed_columns if c not in dataframe.columns]
    if missing:
        raise KeyError(f"Columns not found for suppression: {missing}")
    logger.info("Suppressed columns: %s", suppressed_columns)
    return dataframe.drop(columns=suppressed_columns)


# --------------------------------------------------
# Hashing
# --------------------------------------------------
def hash_columns(
    dataframe: pd.DataFrame,
    columns_with_salt: List[str],
    columns_without_salt: List[str]
) -> pd.DataFrame:

    if not isinstance(columns_with_salt, list) or not isinstance(columns_without_salt, list):
        logger.error("Hashing column lists are not lists: %s, %s",
                     type(columns_with_salt).__name__,
                     type(columns_without_salt).__name__)
        raise TypeError("Hashing column lists must be lists")

    logger.debug("Generated global salt for hashing")
    for col in columns_with_salt:
        salt = generate_global_salt() if columns_with_salt else None
        if col not in dataframe.columns:
            raise KeyError(f"Column '{col}' not found for salted hashing")
        dataframe[col] = dataframe[col].apply(
            lambda x: x if _is_nan_like(x) or str(x).strip() == ""
            else hashlib.sha256((salt + str(x)).encode()).hexdigest()
        )
        logger.info("Applied salted hashing to column: %s", col)

    for col in columns_without_salt:
        if col not in dataframe.columns:
            raise KeyError(f"Column '{col}' not found for hashing")
        dataframe[col] = dataframe[col].apply(
            lambda x: x if _is_nan_like(x) or str(x).strip() == ""
            else hashlib.sha256(str(x).encode()).hexdigest()
        )
        logger.info("Applied hashing to column: %s", col)
    return dataframe


# --------------------------------------------------
# Encryption
# --------------------------------------------------
def encrypt_columns(
    dataframe: pd.DataFrame,
    columns_to_encrypt: List[Any],
    output_directory: str
) -> pd.DataFrame:

    if not isinstance(columns_to_encrypt, list):
        logger.error("columns_to_encrypt is not a list: %s", type(columns_to_encrypt).__name__)
        raise TypeError("columns_to_encrypt must be a list")

    os.makedirs(output_directory, exist_ok=True)
    key_file     = os.path.join(output_directory, "symmetric_keys.json")
    fpe_key_file = os.path.join(output_directory, "fpe_keys.json")  # unified FPE key store

    # Load existing AES keys
    if os.path.exists(key_file):
        try:
            with open(key_file, "r") as f:
                key_map = json.load(f)
        except json.JSONDecodeError as e:
            raise RuntimeError(f"Corrupted key file '{key_file}': {e}")
    else:
        key_map = {}

    # Load unified FPE key store — entries are {"key": hex_str, "mode": "general"|"pan"|"digits"}
    # Backward-compat: plain hex strings (old format) are treated as mode="general"
    if os.path.exists(fpe_key_file):
        try:
            with open(fpe_key_file, "r") as f:
                fpe_key_map = json.load(f)
        except json.JSONDecodeError as e:
            raise RuntimeError(f"Corrupted FPE key file '{fpe_key_file}': {e}")
    else:
        fpe_key_map = {}

    for entry in columns_to_encrypt:
        col, use_fpe = _parse_encrypt_entry(entry)

        if col not in dataframe.columns:
            raise KeyError(f"Column '{col}' not found for encryption")

        if use_fpe:
            existing = fpe_key_map.get(col)
            if isinstance(existing, dict):
                master_key = existing["key"]
            elif isinstance(existing, str):
                master_key = existing  # backward-compat
            else:
                master_key = secrets.token_hex(16)
            fpe_key_map[col] = {"key": master_key, "mode": "general"}

            dataframe[col] = dataframe[col].apply(
                lambda x: x if _is_nan_like(x) else _fpe_encrypt_general(str(x), master_key, col)
            )
            logger.info("Applied format-preserving encryption to column: %s", col)
        else:
            if col in key_map:
                key = base64.b64decode(key_map[col])
            else:
                key = AESGCM.generate_key(bit_length=256)
                key_map[col] = base64.b64encode(key).decode()

            aesgcm = AESGCM(key)

            def _aes_encrypt_value(x):
                if _is_nan_like(x):
                    return x
                plaintext = str(x).encode()
                nonce = os.urandom(12)
                ciphertext = aesgcm.encrypt(nonce, plaintext, None)
                return base64.b64encode(nonce + ciphertext).decode()

            try:
                dataframe[col] = dataframe[col].apply(_aes_encrypt_value)
            except Exception as e:
                raise RuntimeError(f"Encryption failed for column '{col}': {e}")
            logger.info("Encrypted column: %s", col)

    tmp_key_file = key_file + ".tmp"
    try:
        with open(tmp_key_file, "w") as f:
            json.dump(key_map, f, indent=4)
        os.replace(tmp_key_file, key_file)
    except Exception as e:
        raise OSError(f"Failed to write encryption key file: {e}")

    tmp_fpe_key_file = fpe_key_file + ".tmp"
    try:
        with open(tmp_fpe_key_file, "w") as f:
            json.dump(fpe_key_map, f, indent=4)
        os.replace(tmp_fpe_key_file, fpe_key_file)
        os.chmod(fpe_key_file, stat.S_IRUSR | stat.S_IWUSR)
    except Exception as e:
        raise OSError(f"Failed to write FPE key file: {e}")

    return dataframe


# --------------------------------------------------
# Masking
# --------------------------------------------------
def mask_columns(dataframe: pd.DataFrame, masking_info: List[Dict]) -> pd.DataFrame:
    if not isinstance(masking_info, list):
        logger.error("masking_info is not a list: %s", type(masking_info).__name__)
        raise TypeError("masking_info must be a list of dictionaries")

    for mask in masking_info:
        if not isinstance(mask, dict):
            raise ValueError("Each masking entry must be a dictionary")

        column = mask.get("column")
        if not column:
            raise ValueError("Masking config missing 'column'")

        if column not in dataframe.columns:
            raise KeyError(f"Column '{column}' not found for masking")
        
        
        masking_character = mask.get("masking_char", mask.get("masking_character", "*"))
        characters_to_mask = mask.get("characters_to_mask", [])
        regex_patterns = mask.get("regex_patterns", [])
        class_masking_mode = mask.get("class_masking_mode")
        class_letter = mask.get("class_mask_letter", "X")
        class_digit = mask.get("class_mask_digit", "0")
        apply_order = mask.get("apply_order", ["characters", "regex", "class"])

        if not isinstance(masking_character, str) or len(masking_character) != 1:
            raise ValueError("'masking_char' must be a single character")

        if (not isinstance(characters_to_mask, list) or
            not all(isinstance(i, int) and i > 0 for i in characters_to_mask)):
            raise ValueError("'characters_to_mask' must be a list of positive integers")

        if not isinstance(regex_patterns, list):
            raise ValueError("'regex_patterns' must be a list")

        if class_masking_mode not in (None, "random_class", "fixed_class"):
            raise ValueError("'class_masking_mode' must be one of: random_class, fixed_class")
        if not isinstance(apply_order, list):
            raise ValueError("'apply_order' must be a list")
        allowed_steps = {"characters", "regex", "class"}
        if any(step not in allowed_steps for step in apply_order):
            raise ValueError("'apply_order' supports only: characters, regex, class")
        if len(apply_order) != len(set(apply_order)):
            raise ValueError("'apply_order' cannot contain duplicate steps")

        def _derive_regex(pattern_config: Dict) -> str:
            pattern_type = str(pattern_config.get("type", "")).strip().lower()
            delimiter = pattern_config.get("delimiter")
            start = pattern_config.get("start")
            end = pattern_config.get("end")

            if pattern_type == "before" and delimiter is not None:
                return rf"^.+?(?={re.escape(str(delimiter))})"

            if pattern_type == "after" and delimiter is not None:
                return rf"(?<={re.escape(str(delimiter))}).+$"

            if pattern_type == "in_between" and start is not None and end is not None:
                if str(end) == "$":
                    return rf"(?<={re.escape(str(start))}).+$"
                return rf"(?<={re.escape(str(start))}).+?(?={re.escape(str(end))})"

            return ""

        def _apply_delimiter_length_mask(
            text_value: str,
            pattern_config: Dict,
            pattern_masking_char: str
        ) -> Tuple[str, bool]:
            """
            Apply partial masking around a delimiter when `length` is provided.
            - type=after: masks exactly `length` chars after delimiter
            - type=before: masks exactly `length` chars before delimiter
            """
            pattern_type = str(pattern_config.get("type", "")).strip().lower()
            delimiter = pattern_config.get("delimiter")
            length = pattern_config.get("length")

            if pattern_type not in {"before", "after"}:
                return text_value, False
            if delimiter is None or length is None:
                return text_value, False

            try:
                n = int(length)
            except Exception:
                raise ValueError("'length' in regex pattern must be an integer")

            if n <= 0:
                raise ValueError("'length' in regex pattern must be > 0")

            delim = str(delimiter)
            if not delim:
                raise ValueError("'delimiter' in regex pattern cannot be empty")

            chars = list(text_value)
            changed = False
            search_start = 0
            while True:
                idx = text_value.find(delim, search_start)
                if idx == -1:
                    break

                if pattern_type == "after":
                    start_idx = idx + len(delim)
                    end_idx = min(len(chars), start_idx + n)
                else:
                    end_idx = idx
                    start_idx = max(0, end_idx - n)

                for i in range(start_idx, end_idx):
                    chars[i] = pattern_masking_char
                    changed = True

                search_start = idx + len(delim)

            return "".join(chars), changed

        def _regex_mask_value(text_value: str) -> str:
            masked = text_value
            for pattern_config in regex_patterns:
                if not isinstance(pattern_config, dict):
                    raise ValueError("Each regex pattern entry must be a dictionary")

                pattern_masking_char = pattern_config.get("masking_char", masking_character)
                if not isinstance(pattern_masking_char, str) or len(pattern_masking_char) != 1:
                    raise ValueError("'masking_char' inside regex pattern must be a single character")

                masked_by_length, changed = _apply_delimiter_length_mask(
                    masked,
                    pattern_config,
                    pattern_masking_char
                )
                if changed:
                    masked = masked_by_length
                    continue

                regex_pattern = pattern_config.get("regex")
                derived_pattern = _derive_regex(pattern_config)
                regex_obj = None

                if regex_pattern:
                    try:
                        regex_obj = re.compile(regex_pattern)
                    except re.error as e:
                        if derived_pattern:
                            logger.warning(
                                "Invalid regex '%s' for column '%s': %s. Falling back to derived regex '%s'.",
                                regex_pattern,
                                column,
                                e,
                                derived_pattern,
                            )
                            regex_obj = re.compile(derived_pattern)
                        else:
                            raise ValueError(f"Invalid regex '{regex_pattern}': {e}")
                elif derived_pattern:
                    regex_obj = re.compile(derived_pattern)
                else:
                    raise ValueError(
                        "Each regex pattern must include a valid 'regex' or derivable 'type' config"
                    )

                mask_groups = pattern_config.get("mask_groups")
                if mask_groups:
                    if not isinstance(mask_groups, dict):
                        raise ValueError("'mask_groups' must be a dictionary {group_index: mode}")

                    def _group_mask_replacer(match: re.Match) -> str:
                        groups = list(match.groups())
                        for key, mode in mask_groups.items():
                            idx = int(key) - 1
                            if idx < 0 or idx >= len(groups):
                                continue
                            group_val = groups[idx]
                            if group_val is None:
                                continue

                            if mode == "full":
                                groups[idx] = pattern_masking_char * len(group_val)
                            elif mode == "partial":
                                if len(group_val) <= 1:
                                    groups[idx] = group_val
                                else:
                                    groups[idx] = group_val[0] + (pattern_masking_char * (len(group_val) - 1))
                            else:
                                raise ValueError("mask_groups mode must be 'full' or 'partial'")

                        rebuilt = match.group(0)
                        for original, replacement in zip(match.groups(), groups):
                            if original is None:
                                continue
                            rebuilt = rebuilt.replace(original, replacement, 1)
                        return rebuilt

                    masked, _ = regex_obj.subn(_group_mask_replacer, masked)
                else:
                    masked, replaced = regex_obj.subn(
                        lambda m: pattern_masking_char * len(m.group(0)),
                        masked
                    )
                    if replaced == 0 and str(pattern_config.get("type", "")).strip().lower() == "in_between":
                        # Data-adaptive fallback for values like "BSKY SCHEME" when configured delimiters are absent.
                        if " " in masked:
                            masked = re.sub(
                                r"(?<=\s).+$",
                                lambda m: pattern_masking_char * len(m.group(0)),
                                masked
                            )
            return masked

        def _char_class_mask(value: str) -> str:
            out = []
            for c in value:
                if c.isdigit():
                    out.append(secrets.choice(string.digits))
                elif c.isupper():
                    out.append(secrets.choice(string.ascii_uppercase))
                elif c.islower():
                    out.append(secrets.choice(string.ascii_lowercase))
                else:
                    out.append(c)
            return "".join(out)

        def _class_fixed_mask(value: str, letter: str = "X", digit: str = "0") -> str:
            out = []
            for c in value:
                if c.isdigit():
                    out.append(digit)
                elif c.isalpha():
                    out.append(letter)
                else:
                    out.append(c)
            return "".join(out)

        def mask_value(value):
            if _is_nan_like(value):
                return value

            masked = str(value)

            for step in apply_order:
                if step == "characters" and characters_to_mask:
                    s = list(masked)
                    n = len(s)
                    for pos in characters_to_mask:
                        idx = pos - 1
                        if 0 <= idx < n:
                            s[idx] = masking_character
                    masked = ''.join(s)

                elif step == "regex" and regex_patterns:
                    # regex patterns are applied in listed order
                    masked = _regex_mask_value(masked)

                elif step == "class":
                    if class_masking_mode == "random_class":
                        masked = _char_class_mask(masked)
                    elif class_masking_mode == "fixed_class":
                        masked = _class_fixed_mask(masked, class_letter, class_digit)

            return masked


        dataframe[column] = dataframe[column].apply(mask_value)
        logger.info("Masked column: %s", column)
    return dataframe


# --------------------------------------------------
# Charcloak (character-class preserving randomization)
# --------------------------------------------------
def charcloak_columns(dataframe: pd.DataFrame, columns: List[str]) -> pd.DataFrame:
    if not isinstance(columns, list):
        raise TypeError("charcloak must be a list of column names")

    for col in columns:
        if col not in dataframe.columns:
            raise KeyError(f"Column '{col}' not found for charcloak")

        def _charcloak_value(value):
            if _is_nan_like(value):
                return value

            text = str(value)
            out = []
            for c in text:
                if c.isdigit():
                    out.append(secrets.choice(string.digits))
                elif c.isupper():
                    out.append(secrets.choice(string.ascii_uppercase))
                elif c.islower():
                    out.append(secrets.choice(string.ascii_lowercase))
                else:
                    out.append(c)
            return "".join(out)

        dataframe[col] = dataframe[col].apply(_charcloak_value)
        logger.info("Applied charcloak to column: %s", col)

    return dataframe


# --------------------------------------------------
# FPE (format-preserving encryption)
# --------------------------------------------------
def _derive_key(master_key: str, context: str) -> bytes:
    return hmac.new(
        master_key.encode(),
        context.encode(),
        hashlib.sha256
    ).digest()[:16]


def _get_pyffx():
    try:
        import pyffx
    except Exception as e:
        raise RuntimeError(
            f"pyffx dependency is required for FPE operations: {e}"
        )
    return pyffx


def _fpe_pan_encrypt(value: str, master_key: str) -> str:
    if value is None:
        return None

    pan = str(value)
    if not re.fullmatch(r"[A-Z]{5}[0-9]{4}[A-Z]", pan):
        return pan

    pyffx = _get_pyffx()
    key_letters = _derive_key(master_key, "pan_letters")
    key_digits = _derive_key(master_key, "pan_digits")
    key_suffix = _derive_key(master_key, "pan_suffix")

    cipher_letters_5 = pyffx.String(
        pyffx.FFX(key_letters),
        alphabet=string.ascii_uppercase,
        length=5
    )
    cipher_digits_4 = pyffx.String(
        pyffx.FFX(key_digits),
        alphabet=string.digits,
        length=4
    )
    cipher_letter_1 = pyffx.String(
        pyffx.FFX(key_suffix),
        alphabet=string.ascii_uppercase,
        length=1
    )

    return (
        cipher_letters_5.encrypt(pan[:5]) +
        cipher_digits_4.encrypt(pan[5:9]) +
        cipher_letter_1.encrypt(pan[9])
    )


def _fpe_digits_encrypt(value: str, master_key: str) -> str:
    if value is None:
        return None

    raw = str(value)
    if not raw.isdigit():
        return raw

    pyffx = _get_pyffx()
    context = f"digits_len_{len(raw)}"
    key = _derive_key(master_key, context)
    cipher = pyffx.String(
        pyffx.FFX(key),
        alphabet=string.digits,
        length=len(raw)
    )
    return cipher.encrypt(raw)


def _fpe_encrypt_general(value: str, master_key: str, column_name: str) -> str:
    """
    Segment-wise FPE:
    - uppercase runs encrypted with uppercase alphabet
    - lowercase runs encrypted with lowercase alphabet
    - digit runs encrypted with digit alphabet
    - non-alnum separators preserved
    """
    pyffx = _get_pyffx()
    out = []
    i = 0
    text = str(value)

    while i < len(text):
        ch = text[i]
        if ch.isupper():
            cls = "upper"
            alphabet = string.ascii_uppercase
        elif ch.islower():
            cls = "lower"
            alphabet = string.ascii_lowercase
        elif ch.isdigit():
            cls = "digit"
            alphabet = string.digits
        else:
            out.append(ch)
            i += 1
            continue

        j = i + 1
        while j < len(text):
            nxt = text[j]
            if cls == "upper" and nxt.isupper():
                j += 1
                continue
            if cls == "lower" and nxt.islower():
                j += 1
                continue
            if cls == "digit" and nxt.isdigit():
                j += 1
                continue
            break

        segment = text[i:j]
        key = _derive_key(master_key, f"{column_name}:{cls}:{len(segment)}")
        cipher = pyffx.String(pyffx.FFX(key), alphabet=alphabet, length=len(segment))
        out.append(cipher.encrypt(segment))
        i = j

    return "".join(out)


def fpe_encrypt_columns(
    dataframe: pd.DataFrame,
    fpe_info: List[Dict],
    output_directory: str
) -> pd.DataFrame:
    if not isinstance(fpe_info, list):
        raise TypeError("fpe_info must be a list of dictionaries")

    if not fpe_info:
        return dataframe

    os.makedirs(output_directory, exist_ok=True)
    key_file = os.path.join(output_directory, "fpe_keys.json")  # unified FPE key store

    # Entries: {"key": hex_str, "mode": "pan"|"digits"|"general"}
    # Backward-compat: plain hex strings (old format) are treated as mode="digits"
    if os.path.exists(key_file):
        try:
            with open(key_file, "r") as f:
                key_map = json.load(f)
        except json.JSONDecodeError as e:
            raise RuntimeError(f"Corrupted FPE key file '{key_file}': {e}")
    else:
        key_map = {}

    for entry in fpe_info:
        if not isinstance(entry, dict):
            raise ValueError("Each FPE entry must be a dictionary")

        column = entry.get("column")
        if not column:
            raise ValueError("FPE config missing 'column'")
        if column not in dataframe.columns:
            raise KeyError(f"Column '{column}' not found for FPE")

        fpe_format = entry.get("format", "pan")
        if fpe_format not in {"pan", "digits"}:
            raise ValueError("Currently supported FPE formats: 'pan', 'digits'")

        existing = key_map.get(column)
        if isinstance(existing, dict):
            master_key = existing["key"]
        elif isinstance(existing, str):
            master_key = existing  # backward-compat
        else:
            master_key = secrets.token_hex(16)
        key_map[column] = {"key": master_key, "mode": fpe_format}

        if fpe_format == "pan":
            dataframe[column] = dataframe[column].apply(
                lambda x: x if _is_nan_like(x) else _fpe_pan_encrypt(str(x), master_key)
            )
        else:
            dataframe[column] = dataframe[column].apply(
                lambda x: x if _is_nan_like(x) else _fpe_digits_encrypt(str(x), master_key)
            )
        logger.info("Applied FPE to column: %s", column)

    tmp_key_file = key_file + ".tmp"
    try:
        with open(tmp_key_file, "w") as f:
            json.dump(key_map, f, indent=4)
        os.replace(tmp_key_file, key_file)
        os.chmod(key_file, stat.S_IRUSR | stat.S_IWUSR)
    except Exception as e:
        raise OSError(f"Failed to write FPE key file: {e}")

    return dataframe


# --------------------------------------------------
# Vault tokenization
# --------------------------------------------------
def tokenize_columns(
    dataframe: pd.DataFrame,
    tokenization_info: List[Dict],
    output_directory: str
) -> pd.DataFrame:
    if not isinstance(tokenization_info, list):
        raise TypeError("tokenization_info must be a list of dictionaries")

    if not tokenization_info:
        return dataframe

    os.makedirs(output_directory, exist_ok=True)
    vault_file = os.path.join(output_directory, "token_vault.json")

    if os.path.exists(vault_file):
        try:
            with open(vault_file, "r") as f:
                vault = json.load(f)
        except json.JSONDecodeError as e:
            raise RuntimeError(f"Corrupted token vault '{vault_file}': {e}")
    else:
        vault = {}

    def _new_token(existing_reverse: Dict[str, str], prefix: str, digits: int) -> str:
        while True:
            token = prefix + "".join(secrets.choice(string.digits) for _ in range(digits))
            if token not in existing_reverse:
                return token

    for entry in tokenization_info:
        if not isinstance(entry, dict):
            raise ValueError("Each tokenization entry must be a dictionary")

        column = entry.get("column")
        if not column:
            raise ValueError("Tokenization config missing 'column'")
        if column not in dataframe.columns:
            raise KeyError(f"Column '{column}' not found for tokenization")

        prefix = entry.get("prefix", "TK-")
        digits = int(entry.get("digits", 6))
        if digits <= 0:
            raise ValueError("'digits' for tokenization must be > 0")

        col_vault = vault.setdefault(column, {"forward": {}, "reverse": {}})
        forward = col_vault["forward"]
        reverse = col_vault["reverse"]

        def _tokenize(value):
            if _is_nan_like(value):
                return value

            source = str(value)
            if source in forward:
                return forward[source]

            token = _new_token(reverse, prefix, digits)
            forward[source] = token
            reverse[token] = source
            return token

        dataframe[column] = dataframe[column].apply(_tokenize)
        logger.info("Applied tokenization to column: %s", column)

    tmp_vault_file = vault_file + ".tmp"
    try:
        with open(tmp_vault_file, "w") as f:
            json.dump(vault, f, indent=2)
        os.replace(tmp_vault_file, vault_file)
        os.chmod(vault_file, stat.S_IRUSR | stat.S_IWUSR)
    except Exception as e:
        raise OSError(f"Failed to write token vault: {e}")

    return dataframe
