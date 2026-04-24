
import smtplib
import random
from email.message import EmailMessage
from config import Config

def generate_code() -> str:
    """Generates a 6-digit OTP code."""
    return str(random.randint(100000, 999999))

def send_verification_email(to_email: str, code: str) -> tuple[bool, str]:
    """Sends a verification email with the OTP code."""
    
    email_address = Config.MAIL_USERNAME
    email_password = Config.MAIL_PASSWORD
    
    if not email_address or not email_password:
        return False, "Email credentials are not set. Add MAIL_USERNAME and MAIL_PASSWORD in .env."

    msg = EmailMessage()
    msg["Subject"] = "Your Verification Code - Encripy"
    msg["From"] = email_address
    msg["To"] = to_email
    msg.set_content(f"Your verification code is: {code}\n\nThis code will expire in 10 minutes.")

    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(email_address, email_password)
            server.send_message(msg)
            return True, f"Verification email sent to {to_email}."
    except Exception as e:
        return False, f"Failed to send email: {e}"
