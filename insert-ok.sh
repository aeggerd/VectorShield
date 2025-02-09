# 1. PayPal Transaction Confirmation (Legitimate)
curl -X POST "http://localhost:5000/insert" -H "Content-Type: application/json" -d '{
  "subject": "PayPal Payment Receipt for Your Purchase",
  "body": "Thank you for your purchase! Your PayPal transaction ID is 123456789. View your receipt at https://paypal.com",
  "sender": "service@paypal.com",
  "type": "legitimate"
}'

# 2. Bank Statement Notification (Legitimate)
curl -X POST "http://localhost:5000/insert" -H "Content-Type: application/json" -d '{
  "subject": "Your Monthly Bank Statement is Ready",
  "body": "Your latest bank statement is available in your online banking account. View it securely at https://yourbank.com",
  "sender": "alerts@yourbank.com",
  "type": "legitimate"
}'

# 3. Amazon Order Confirmation (Legitimate)
curl -X POST "http://localhost:5000/insert" -H "Content-Type: application/json" -d '{
  "subject": "Amazon Order #12345 Confirmed",
  "body": "Thank you for your purchase! Your order has been shipped and will arrive soon. Track it here: https://amazon.com/track",
  "sender": "orders@amazon.com",
  "type": "legitimate"
}'

# 4. Microsoft Account Security Notice (Legitimate)
curl -X POST "http://localhost:5000/insert" -H "Content-Type: application/json" -d '{
  "subject": "Microsoft Account Security Update",
  "body": "We have added extra security to your Microsoft account. Visit https://account.microsoft.com to learn more.",
  "sender": "security@microsoft.com",
  "type": "legitimate"
}'

# 5. Crypto Wallet Deposit Confirmation (Legitimate)
curl -X POST "http://localhost:5000/insert" -H "Content-Type: application/json" -d '{
  "subject": "Your Crypto Wallet Deposit is Successful",
  "body": "Your deposit of 0.5 BTC has been confirmed. Check your balance at https://crypto-wallet.com",
  "sender": "noreply@crypto-wallet.com",
  "type": "legitimate"
}'

# 6. Facebook Login Notification (Legitimate)
curl -X POST "http://localhost:5000/insert" -H "Content-Type: application/json" -d '{
  "subject": "Your Facebook Login on a New Device",
  "body": "You logged in from a new device. If this wasnt you, reset your password at https://facebook.com/security",
  "sender": "notifications@facebook.com",
  "type": "legitimate"
}'

# 7. Apple ID Purchase Confirmation (Legitimate)
curl -X POST "http://localhost:5000/insert" -H "Content-Type: application/json" -d '{
  "subject": "Your Apple ID Purchase Receipt",
  "body": "Thank you for your purchase on the App Store. View your receipt at https://apple.com/billing",
  "sender": "billing@apple.com",
  "type": "legitimate"
}'

# 8. Official IRS Tax Refund Notification (Legitimate)
curl -X POST "http://localhost:5000/insert" -H "Content-Type: application/json" -d '{
  "subject": "IRS Tax Refund Status Update",
  "body": "Your tax refund status has been updated. View details securely at https://irs.gov/refund",
  "sender": "no-reply@irs.gov",
  "type": "legitimate"
}'

# 9. DHL Shipping Notification (Legitimate)
curl -X POST "http://localhost:5000/insert" -H "Content-Type: application/json" -d '{
  "subject": "DHL Shipment 789456 is On Its Way",
  "body": "Your package is on the way! Track your delivery at https://dhl.com/track",
  "sender": "notifications@dhl.com",
  "type": "legitimate"
}'

# 10. Job Offer Confirmation (Legitimate)
curl -X POST "http://localhost:5000/insert" -H "Content-Type: application/json" -d '{
  "subject": "Your Job Application Status Update",
  "body": "We have received your job application and will review it soon. You can check your status at https://jobs.company.com",
  "sender": "hr@company.com",
  "type": "legitimate"
}'

