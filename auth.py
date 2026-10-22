
from werkzeug.security import generate_password_hash, check_password_hash

# Create a secure password hash
def hash_password(password):
    return generate_password_hash(password)

# Check a password against its saved hash
def verify_password(password, saved_hash):
    return check_password_hash(saved_hash, password)


if __name__ == "__main__":
    password = input("Enter a test password: ")
    saved_hash = hash_password(password)

    print("Password hash created successfully.")
    print("Password verification:", verify_password(password, saved_hash))
