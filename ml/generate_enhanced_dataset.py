"""
Enhanced dataset generator for Indian scam detection.
Creates diverse, realistic scam and safe messages covering multiple patterns.
"""
import pandas as pd
import random
from typing import List, Tuple

random.seed(42)

# ============================================================================
# SCAM MESSAGE TEMPLATES
# ============================================================================

# OTP / Bank Fraud
OTP_BANK_SCAMS = [
    "Your {bank} account is blocked. Call {phone} to verify your KYC immediately.",
    "RBI Alert: Your account will be suspended. Share OTP to reactivate: {otp}",
    "Dear customer, your {card} is blocked. Click {link} to unlock.",
    "Your {bank} debit card has been used for Rs {amount}. If not you, call {phone}",
    "URGENT: Your account shows suspicious activity. Verify at {link} or call {phone}",
    "Your {bank} account will be closed in 24 hours. Update KYC: {link}",
    "Security Alert: Someone logged into your {bank} account from {city}. Call {phone}",
    "Your ATM card is expired. Update details at {link} to avoid account freeze",
    "Dear customer, your account has been debited Rs {amount}. Call {phone} if unauthorized",
    "RBI Notice: Your PAN card is not linked. Share OTP {otp} to avoid penalty",
    "Your {bank} mobile banking is locked. Reset PIN by calling {phone}",
    "Account verification pending. Submit Aadhaar OTP {otp} to activate services",
    "{bank} Alert: Unusual transaction detected. Verify OTP {otp} within 1 hour",
    "Your account will be deactivated. Click {link} to submit KYC documents now",
    "Dear customer, your credit card limit is reduced. Call {phone} to restore",
]

# UPI Fraud
UPI_SCAMS = [
    "Send 1 rupee to verify your UPI: {upi}",
    "You won cashback of Rs {amount}! Claim now by sending Rs 10 to {upi}",
    "Receive your OLX payment of Rs {amount}. Scan QR and enter UPI PIN: {link}",
    "Your UPI PIN will expire today. Verify by sending Rs 1 to {upi}",
    "Paytm KYC pending. Send Rs 1 to {upi} to activate full wallet",
    "You have unclaimed refund of Rs {amount}. Collect at {upi}",
    "Google Pay reward Rs {amount} credited. Verify UPI at {upi}",
    "PhonePe offer: Get Rs {amount} cashback. Send Re 1 to {upi} to claim",
    "Your Paytm wallet is locked. Unlock by paying Rs 10 to {upi}",
    "Congratulations! Rs {amount} added to your account. Withdraw at {upi}",
]

# Job Scams
JOB_SCAMS = [
    "Hi, I'm the {role}. You are shortlisted for {position}. Pay Rs {amount} for docs: {upi}",
    "Congratulations! You are hired by {company}. Send Rs {amount} for laptop delivery to: {upi}",
    "Work from home job! Earn {amount} daily. No experience needed. WhatsApp {phone}",
    "Urgent hiring for {position} at {company}. Registration fee Rs {amount}. Contact {phone}",
    "{company} is recruiting. Apply now by paying Rs {amount} document fee: {upi}",
    "Part-time job opportunity! Earn Rs {amount} per week. Send resume to {phone}",
    "You are selected for {position} role. Pay Rs {amount} training fee: {upi}",
    "Genuine work from home. Earn {amount} monthly. Registration: {phone}",
    "Freshers wanted for {position}. One-time fee Rs {amount}. Apply: {upi}",
    "Remote job at {company}. Send Rs {amount} for offer letter: {upi}",
]

# Lottery / Prize Scams
LOTTERY_SCAMS = [
    "You have won Rs {amount} in {program} lottery! Call {phone} to claim your prize.",
    "{company} lucky draw! You won {prize}. Pay Rs {fee} shipping: {link}",
    "Congratulations! You won {prize} in lucky draw. Claim at {link}",
    "KBC Lottery winner! Rs {amount} credited. Verify at {phone}",
    "You are selected for {program} prize of Rs {amount}. Call {phone} now",
    "{company} bumper offer! You won {prize}. Pay Rs {fee} for delivery: {upi}",
    "Lucky winner! You won Rs {amount}. Claim fee Rs {fee}: {upi}",
    "Your phone number won {prize} in {company} draw. Contact {phone}",
    "Congratulations! Rs {amount} prize money. Processing fee Rs {fee}: {upi}",
    "You won {prize} in lucky draw. Courier charges Rs {fee}: {link}",
]

# Authority / Digital Arrest
AUTHORITY_SCAMS = [
    "This is {authority}. A case has been filed against your Aadhaar. Pay fine of Rs {amount} or face arrest.",
    "Your electricity connection will be cut in 2 hours. Pay pending bill now: {link}",
    "Income Tax Notice: Pay pending Rs {amount} tax immediately. Visit {link}",
    "Police Notice: Your Aadhaar is used in illegal activity. Pay Rs {amount} penalty: {phone}",
    "{authority} Alert: Arrest warrant issued. Pay Rs {amount} fine to cancel: {link}",
    "Your gas connection will be terminated. Clear dues Rs {amount}: {upi}",
    "Cyber Crime Notice: Your number is linked to fraud. Pay Rs {amount}: {phone}",
    "Court summons issued. Settle case by paying Rs {amount}: {link}",
    "Traffic Police: Challan of Rs {amount} pending. Pay now: {link}",
    "Your mobile number will be blocked. Clear pending Rs {amount}: {phone}",
]

# Emotional / Social Engineering
EMOTIONAL_SCAMS = [
    "Bhai urgent accident ho gaya hai, help chahiye. Is UPI pe bhej do: {upi}",
    "Mummy phone chori ho gaya hai, naye number pe {amount} bhej do: {upi}",
    "Papa hospital mein hain, urgent {amount} chahiye. Send to {upi}",
    "Beta, bahut emergency hai. {amount} bhej do is number pe: {phone}",
    "Your friend had an accident. Send Rs {amount} for treatment: {upi}",
    "Son in police custody. Send Rs {amount} immediately to {upi}",
    "Sister's wedding urgent expense. Send Rs {amount}: {upi}",
    "Bhai bike accident, hospital bill Rs {amount}. Help: {upi}",
    "Papa ko heart attack hua. ICU fee Rs {amount} urgent: {phone}",
    "Beta kidnapped. Don't call police. Send Rs {amount} to {upi}",
]

# Investment / Crypto Scams
INVESTMENT_SCAMS = [
    "Invest Rs {amount} in cryptocurrency. Double returns in {days} days. Register: {link}",
    "Stock market tips! Earn Rs {profit} daily. Join now: {phone}",
    "Government scheme: Invest Rs {amount}, get Rs {profit} return. Apply: {upi}",
    "Guaranteed returns! Invest Rs {amount}, earn Rs {profit}. WhatsApp {phone}",
    "Bitcoin trading opportunity. Rs {amount} investment = Rs {profit} profit. Join: {link}",
    "MLM opportunity! Earn Rs {profit} monthly. Registration Rs {amount}: {upi}",
    "Real estate investment. Rs {amount} becomes Rs {profit}. Book now: {phone}",
    "Gold investment scheme. Pay Rs {amount}, get {profit} returns: {link}",
    "Forex trading signals. Earn Rs {profit} daily. Fee Rs {amount}: {upi}",
    "Share market secret tips. Invest Rs {amount}, profit guaranteed: {phone}",
]

# Delivery / E-commerce Scams
DELIVERY_SCAMS = [
    "Your {product} delivery is pending. Pay Rs {amount} customs fee: {link}",
    "{company} COD order. Pay Rs {amount} advance for delivery: {upi}",
    "Parcel from {country} held at customs. Clear Rs {amount} duty: {phone}",
    "Your Amazon order requires Re-verification. Update payment: {link}",
    "Flipkart delivery failed. Confirm address and pay Rs {amount}: {link}",
    "Speed Post parcel pending. Pay Rs {amount} charges: {upi}",
    "International courier delivery. Customs fee Rs {amount}: {phone}",
    "Your package is ready. Pay Rs {amount} shipping: {link}",
    "COD order confirmation needed. Advance Rs {amount}: {upi}",
    "Delivery on hold. Pay Rs {amount} re-delivery charges: {phone}",
]

# Hinglish Variations
HINGLISH_SCAMS = [
    "Aapka {bank} account block ho gaya hai. Turant call karein {phone}",
    "OTP share karo jaldi, account band ho jayega: {otp}",
    "Salary nahi aayi? HR se contact karo {phone} pe",
    "Bhai free iPhone jeetne ka mauka. Rs {amount} bhejo: {upi}",
    "Tumhara UPI verify karna hai. Rs 1 bhejo {upi} pe",
    "Account update karo warna band ho jayega: {link}",
    "Paytm mein {amount} rupay credited hain. Claim karo: {upi}",
    "Amazon lucky draw jeeta hai. {amount} delivery charges bhejo: {upi}",
    "Police case hai tumhare Aadhaar pe. Fine bharo {amount}: {phone}",
    "Maa ko emergency hai. Jaldi {amount} bhejo: {upi}",
]

# ============================================================================
# SAFE MESSAGE TEMPLATES
# ============================================================================

SAFE_MESSAGES = [
    "Hey, are we still meeting for dinner at {time} tonight?",
    "Mom says the food is ready, come home soon from the office.",
    "Please send the project report by Monday morning. Thanks!",
    "I'll be late for the meeting, stuck in traffic near {place}.",
    "Did you see the new update on the company portal about holidays?",
    "Your order has been shipped and will arrive by {day}.",
    "Happy birthday! Hope you have a great year ahead.",
    "The meeting has been rescheduled to {time}. Please confirm.",
    "Mom: I paid the electricity bill online. Receipt is on your WhatsApp.",
    "Let's catch up this weekend. Are you free on Saturday?",
    "Can you pick up groceries on your way home? Need milk and bread.",
    "Don't forget about the presentation tomorrow at {time}.",
    "The client liked our proposal. Great work team!",
    "Lunch at the usual place? I'll be there by {time}.",
    "Your flight booking for {city} is confirmed. Check your email.",
    "Reminder: Doctor's appointment on {day} at {time}.",
    "Thanks for your help yesterday. Really appreciate it!",
    "The package you ordered was delivered to your doorstep.",
    "See you at the gym tomorrow morning at {time}.",
    "Did you finish watching that series? No spoilers please!",
    "Can you share the meeting notes from yesterday's call?",
    "Your cab will arrive in 5 minutes. Driver: {name}",
    "Congratulations on your promotion! Well deserved.",
    "The weather looks good for the picnic on Sunday.",
    "Your subscription has been renewed successfully. Thank you!",
    "Please review the attached document and share feedback.",
    "Your train ticket from {city1} to {city2} is confirmed.",
    "The event starts at {time}. Don't be late!",
    "Your exam results have been published. Check the portal.",
    "Dinner was amazing! Thanks for the recommendation.",
    "Your laptop repair is complete. You can pick it up anytime.",
    "The team outing is planned for next Friday. Mark your calendar.",
    "Your application has been received. We'll get back to you soon.",
    "Happy anniversary! Wishing you many more years of happiness.",
    "The match starts at {time}. Are you watching?",
    "Your internet bill for this month is Rs {amount}.",
    "Thanks for attending the webinar. Here's the recording link.",
    "Your gym membership has been renewed for another year.",
    "The party is at {name}'s place at {time}. See you there!",
    "Your assignment has been graded. Good work!",
]

# Legitimate OTP messages
LEGITIMATE_OTP = [
    "Your OTP for {service} login is {otp}. Do not share this with anyone.",
    "{otp} is your verification code for {service}. Valid for 10 minutes.",
    "Use {otp} to complete your transaction on {service}.",
    "Your {service} account verification code is {otp}.",
    "{service}: Your one-time password is {otp}. Do not share.",
]

# Legitimate transaction messages
LEGITIMATE_TRANSACTIONS = [
    "Your transaction of Rs {amount} at {merchant} was successful.",
    "Rs {amount} debited from your account for {service} subscription.",
    "Payment of Rs {amount} received. Thank you for your purchase.",
    "Your UPI payment of Rs {amount} to {merchant} is successful.",
    "Rs {amount} credited to your account. Balance: Rs {balance}.",
]

# ============================================================================
# DATA GENERATORS
# ============================================================================

# Replacement values
BANKS = ["SBI", "HDFC", "ICICI", "Axis Bank", "PNB", "Bank of India", "Kotak"]
CARDS = ["debit card", "credit card", "ATM card"]
CITIES = ["Delhi", "Mumbai", "Bangalore", "Pune", "Hyderabad", "Chennai"]
PHONES = ["9876543210", "9988776655", "8877665544", "7766554433", "9123456789"]
UPIS = ["verify@paytm", "help@ybl", "urgent@oksbi", "payment@okaxis", "collect@okicici"]
LINKS = ["http://bit.ly/verify", "http://sbi-verify.com", "http://v.ht/pay", "http://tinyurl.com/xyz"]
COMPANIES = ["Google", "Amazon", "Flipkart", "TCS", "Infosys", "Wipro", "HCL"]
POSITIONS = ["Software Engineer", "Data Entry Operator", "Customer Support", "HR Executive"]
ROLES = ["Senior HR", "Manager", "Team Lead", "Recruiter"]
PRIZES = ["iPhone 15", "Samsung TV", "Rs 50,000 cash", "Laptop", "Gold Coin"]
AUTHORITIES = ["CBI", "Police", "Income Tax", "ED", "Cyber Crime"]
PROGRAMS = ["KBC", "Kaun Banega Crorepati", "Big Boss", "Indian Idol"]
PRODUCTS = ["mobile phone", "laptop", "watch", "shoes", "bag"]
COUNTRIES = ["USA", "UK", "Singapore", "Dubai", "Germany"]
SERVICES = ["Amazon", "Flipkart", "Paytm", "Google Pay", "Bank"]
MERCHANTS = ["grocery store", "restaurant", "Amazon", "pharmacy", "petrol pump"]
NAMES = ["Rahul", "Priya", "Amit", "Sneha", "Ravi", "Anjali"]
PLACES = ["Koramangala", "Whitefield", "Indiranagar", "MG Road", "HSR Layout"]

def fill_template(template: str) -> str:
    """Fill a template with random values."""
    return template.format(
        bank=random.choice(BANKS),
        card=random.choice(CARDS),
        city=random.choice(CITIES),
        phone=random.choice(PHONES),
        upi=random.choice(UPIS),
        link=random.choice(LINKS),
        otp=random.randint(1000, 9999),
        amount=random.choice([500, 1000, 2000, 5000, 10000, 25000, 50000]),
        fee=random.choice([10, 50, 100, 200, 500]),
        profit=random.choice([10000, 25000, 50000, 100000]),
        company=random.choice(COMPANIES),
        position=random.choice(POSITIONS),
        role=random.choice(ROLES),
        prize=random.choice(PRIZES),
        authority=random.choice(AUTHORITIES),
        program=random.choice(PROGRAMS),
        days=random.choice([7, 15, 30, 60]),
        product=random.choice(PRODUCTS),
        country=random.choice(COUNTRIES),
        service=random.choice(SERVICES),
        merchant=random.choice(MERCHANTS),
        name=random.choice(NAMES),
        place=random.choice(PLACES),
        time=random.choice(["6 PM", "7 PM", "8 PM", "10 AM", "3 PM", "5:30 PM"]),
        day=random.choice(["Monday", "Tuesday", "Friday", "tomorrow", "next week"]),
        city1=random.choice(CITIES),
        city2=random.choice(CITIES),
        balance=random.randint(5000, 50000),
    )

def generate_scam_messages(count: int) -> List[str]:
    """Generate diverse scam messages."""
    all_templates = (
        OTP_BANK_SCAMS + UPI_SCAMS + JOB_SCAMS + LOTTERY_SCAMS +
        AUTHORITY_SCAMS + EMOTIONAL_SCAMS + INVESTMENT_SCAMS +
        DELIVERY_SCAMS + HINGLISH_SCAMS
    )

    messages = []
    for _ in range(count):
        template = random.choice(all_templates)
        messages.append(fill_template(template))

    return messages

def generate_safe_messages(count: int) -> List[str]:
    """Generate diverse safe messages."""
    all_templates = SAFE_MESSAGES + LEGITIMATE_OTP + LEGITIMATE_TRANSACTIONS

    messages = []
    for _ in range(count):
        template = random.choice(all_templates)
        messages.append(fill_template(template))

    return messages

def create_enhanced_dataset(scam_count: int = 5000, safe_count: int = 5000) -> pd.DataFrame:
    """Create enhanced dataset with diverse messages."""
    print(f"Generating {scam_count} scam messages...")
    scam_messages = generate_scam_messages(scam_count)

    print(f"Generating {safe_count} safe messages...")
    safe_messages = generate_safe_messages(safe_count)

    # Create dataframe
    df = pd.DataFrame({
        'text': scam_messages + safe_messages,
        'label': [1] * scam_count + [0] * safe_count
    })

    # Shuffle
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)

    print(f"\nDataset created:")
    print(f"  Total samples: {len(df)}")
    print(f"  Scam: {len(df[df['label']==1])} ({len(df[df['label']==1])/len(df)*100:.1f}%)")
    print(f"  Safe: {len(df[df['label']==0])} ({len(df[df['label']==0])/len(df)*100:.1f}%)")
    print(f"  Unique messages: {df['text'].nunique()}")

    return df

if __name__ == "__main__":
    # Generate enhanced dataset
    df = create_enhanced_dataset(scam_count=5000, safe_count=5000)

    # Save to CSV
    output_path = "data/scam_dataset_enhanced.csv"
    df.to_csv(output_path, index=False, encoding='utf-8')
    print(f"\nDataset saved to: {output_path}")

    # Show sample
    print(f"\nSample scam messages:")
    for msg in df[df['label']==1]['text'].head(5):
        print(f"  - {msg}")

    print(f"\nSample safe messages:")
    for msg in df[df['label']==0]['text'].head(5):
        print(f"  - {msg}")
