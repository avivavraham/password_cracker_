import hashlib


def generate_md5_hash(phone_number):
    # Format the phone number as 05X-XXXXXXX
    formatted_phone = f"05{phone_number:08d}"

    # Calculate the MD5 hash of the formatted phone number
    md5_hash = hashlib.md5(formatted_phone.encode()).hexdigest()

    return md5_hash


print(True and False)
phone = '050-0000023'
print(hashlib.md5(phone.encode()).hexdigest())
print(generate_md5_hash(23))
