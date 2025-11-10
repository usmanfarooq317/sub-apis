# 🔐 IBM SUB-API Integration Dashboard (Flask)

This project provides a Flask-based backend and frontend interface to integrate and test IBM APIs, including secure login and utility bill services.  
It automatically generates the required `x-hash`, performs login, and then triggers multiple IBM APIs (Inquiry, Payment, etc.) in sequence.

---

## 🚀 Features

✅ **Secure Authentication**
- Generates IBM `x-hash` using SHA-256 encryption  
- Handles login using MSISDN and PIN  

✅ **Multi-API Execution**
- Runs IBM API calls after successful login:
  - `SubscriberUBP Inquiry`
  - `SubscriberUtilityBill Inquiry`
  - `SubscriberUtilityBill Payment`

✅ **Error Handling**
- Detects incorrect PIN or failed login  
- Returns a clear JSON error and displays an alert on the frontend  

✅ **Frontend Included**
- Simple HTML interface with a prefilled default MSISDN (`923319154345`)  
- Built-in request/response display area  

---

## 🧱 Project Structure

