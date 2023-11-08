import hashlib


def generate_md5_hash(phone_number):
    # Format the phone number as 05X-XXXXXXX
    formatted_phone = f"05{phone_number:08d}"

    # Calculate the MD5 hash of the formatted phone number
    md5_hash = hashlib.md5(formatted_phone.encode()).hexdigest()

    return md5_hash

max_value = 86348297
min_value = 27126586
SPLIT = 4
hashed_password = "8634"
hashed_password_index = 0
range_for_process = (max_value - min_value + 1) // SPLIT
split_of_range = [(i * range_for_process, (i + 1) * range_for_process,
                   hashed_password, hashed_password_index) for i in range(SPLIT - 1)]
split_of_range.append((split_of_range[-1][1], max_value, hashed_password, hashed_password_index))
print(split_of_range)