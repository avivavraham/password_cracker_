import hashlib

"""
This Python script transforms a list of phone numbers into a specific format, 05X-XXXXXXX,
 and subsequently generates their corresponding MD5 hash codes.
  The script then saves these phone numbers and their associated hash codes into a text file named `hash_codes.txt`.
"""


def generate_md5_hash(phone_number):
    # Format the phone number as 05X-XXXXXXX
    formatted_phone = f"05{phone_number:08d}"
    formatted_phone = formatted_phone[:3] + "-" + formatted_phone[3:]

    # Calculate the MD5 hash of the formatted phone number
    md5_hash = hashlib.md5(formatted_phone.encode()).hexdigest()

    return md5_hash


def generate_hash_file(phone_numbers):
    with open("hash_codes.txt", "w") as file:
        for number in phone_numbers:
            hash_code = generate_md5_hash(number)
            file.write(f"{number}: {hash_code}\n")


phone_list = [12345678, 87654321, 55555555]  # Example list of phone numbers
generate_hash_file(phone_list)
