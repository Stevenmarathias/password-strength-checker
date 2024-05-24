# password-strength-checker

This is a simple Python script to check the strength of a password based on various criteria such as length, use of uppercase and lowercase letters, numbers, and special characters.

## Usage

Run the script and enter a password to check its strength and get suggestions for improvement.

```bash
python password_strength_checker.py

cd password-strength-checker

import re

def check_password_strength(password):
    # Minimum length requirement
    min_length = 8
    # Criteria for a strong password
    length_criteria = len(password) >= min_length
    lowercase_criteria = re.search(r'[a-z]', password) is not None
    uppercase_criteria = re.search(r'[A-Z]', password) is not None
    number_criteria = re.search(r'[0-9]', password) is not None
    special_char_criteria = re.search(r'[\W_]', password) is not None
    
    # Calculate strength score
    strength_score = sum([length_criteria, lowercase_criteria, uppercase_criteria, number_criteria, special_char_criteria])
    
    # Evaluate strength based on the score
    if strength_score == 5:
        strength = "Very Strong"
    elif strength_score == 4:
        strength = "Strong"
    elif strength_score == 3:
        strength = "Medium"
    elif strength_score == 2:
        strength = "Weak"
    else:
        strength = "Very Weak"
    
    return strength

def suggest_improvements(password):
    suggestions = []
    if len(password) < 8:
        suggestions.append("Increase the length to at least 8 characters.")
    if not re.search(r'[a-z]', password):
        suggestions.append("Add at least one lowercase letter.")
    if not re.search(r'[A-Z]', password):
        suggestions.append("Add at least one uppercase letter.")
    if not re.search(r'[0-9]', password):
        suggestions.append("Add at least one number.")
    if not re.search(r'[\W_]', password):
        suggestions.append("Add at least one special character (e.g., !, @, #, $, etc.).")
    
    return suggestions

def main():
    password = input("Enter a password to check its strength: ")
    strength = check_password_strength(password)
    print(f"Password Strength: {strength}")
    
    if strength != "Very Strong":
        print("Suggestions to improve your password:")
        for suggestion in suggest_improvements(password):
            print(f"- {suggestion}")

if __name__ == "__main__":
    main()

