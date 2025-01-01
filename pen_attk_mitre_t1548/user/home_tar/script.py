import hashlib
import os

def hash_student_code(student_code, salt="PTIT"):
    code_with_salt = student_code + salt
    hashed_code = hashlib.sha256(code_with_salt.encode()).hexdigest()
    return hashed_code

student_code = input("Your MSV: ")

hashed_code = hash_student_code(student_code)

print(f"Hash: {hashed_code}")

file_path = f"/home/ubuntu/secret"

try:
    with open(file_path, "w") as file:
        file.write(f"Hash: {hashed_code}\n")
    print(f"Hash has been saved to {file_path}")
except Exception as e:
    print(f"Error: Could not write to file. {e}")

