# 1. Fake PayPal Phishing Email
curl -X POST "http://localhost:5000/insert" -H "Content-Type: application/json" -d '{
  "subject": "Your PayPal account has been locked!",
  "body": "We detected unusual activity. Click here to reset your password: https://bit.ly/fake",
  "sender": "security@paypal-fake.com",
  "type": "phishing"
}'

# 2. Fake Bank Security Alert
curl -X POST "http://localhost:5000/insert" -H "Content-Type: application/json" -d '{
  "subject": "Security Alert: Unusual Login Detected!",
  "body": "A login attempt was made from an unrecognized device. Confirm your identity: http://secure-login-bank.com",
  "sender": "alerts@bank-secure.com",
  "type": "phishing"
}'

# 3. Fake Amazon Order Confirmation Scam
curl -X POST "http://localhost:5000/insert" -H "Content-Type: application/json" -d '{
  "subject": "Amazon Order Confirmed - Payment Required",
  "body": "Your recent order requires additional payment verification. Click here to complete your purchase: https://fake-amazon-payment.com",
  "sender": "support@amazon-fake.com",
  "type": "phishing"
}'

# 4. Fake Microsoft Account Recovery
curl -X POST "http://localhost:5000/insert" -H "Content-Type: application/json" -d '{
  "subject": "Microsoft Account Recovery Notice",
  "body": "Your Microsoft account has been temporarily disabled. Recover it now: http://microsoft-secure-reset.com",
  "sender": "no-reply@microsoft-fake.com",
  "type": "phishing"
}'

# 5. Fake Crypto Wallet Scam
curl -X POST "http://localhost:5000/insert" -H "Content-Type: application/json" -d '{
  "subject": "URGENT: Your Crypto Wallet is at Risk!",
  "body": "Unauthorized access detected! Secure your funds immediately: https://crypto-safety-fake.com",
  "sender": "security@crypto-fake.com",
  "type": "phishing"
}'

# 6. Fake Facebook Security Warning
curl -X POST "http://localhost:5000/insert" -H "Content-Type: application/json" -d '{
  "subject": "Your Facebook Account Will Be Disabled",
  "body": "We have detected suspicious activity on your Facebook account. Verify now: https://facebook-recovery-fake.com",
  "sender": "support@facebook-fake.com",
  "type": "phishing"
}'

# 7. Fake Apple ID Scam
curl -X POST "http://localhost:5000/insert" -H "Content-Type: application/json" -d '{
  "subject": "Apple ID Locked - Verify Your Information",
  "body": "Your Apple ID has been locked due to suspicious login attempts. Restore access here: https://apple-secure-fake.com",
  "sender": "appleid@apple-fake.com",
  "type": "phishing"
}'

# 8. Fake Tax Refund Scam
curl -X POST "http://localhost:5000/insert" -H "Content-Type: application/json" -d '{
  "subject": "You Are Eligible for a Tax Refund!",
  "body": "The IRS has calculated a refund for you. Claim your refund now: https://irs-refund-fake.com",
  "sender": "refund@irs-fake.com",
  "type": "phishing"
}'

# 9. Fake DHL Package Tracking Scam
curl -X POST "http://localhost:5000/insert" -H "Content-Type: application/json" -d '{
  "subject": "Your DHL Package is Waiting for Confirmation",
  "body": "Your package cannot be delivered until you confirm your address: https://dhl-tracking-fake.com",
  "sender": "tracking@dhl-fake.com",
  "type": "phishing"
}'

# 10. Fake Job Offer Scam
curl -X POST "http://localhost:5000/insert" -H "Content-Type: application/json" -d '{
  "subject": "Job Offer: Work From Home & Earn \$5000/Week!",
  "body": "We have an exclusive job opportunity for you. Sign up now: https://job-offer-fake.com",
  "sender": "hr@job-fake.com",
  "type": "phishing"
}'

