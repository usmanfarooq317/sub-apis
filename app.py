# backend/app.py
from flask import Flask, request, jsonify, make_response
from flask_cors import CORS
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
import base64
import requests
import os
import logging

# ---- App init ----
app = Flask(__name__)
CORS(app)  # allow cross-origin calls (you can restrict origins later)

# ---- Configuration (from env, with your previous defaults) ----
IBM_CLIENT_ID = os.environ.get("IBM_CLIENT_ID", "924726a273f72a75733787680810c4e4")
IBM_CLIENT_SECRET = os.environ.get("IBM_CLIENT_SECRET", "7154c95b3351d88cb31302f297eb5a9c")
X_CHANNEL = os.environ.get("X_CHANNEL", "subgateway")
PUBLIC_KEY_PATH = os.path.join(os.path.dirname(__file__), "subgateway.pem")

# ---- Logging ----
logging.basicConfig(level=logging.INFO)

# ---- Load IBM Public Key (PEM) ----
if not os.path.exists(PUBLIC_KEY_PATH):
    app.logger.error("Public key not found at %s", PUBLIC_KEY_PATH)
    raise FileNotFoundError(f"Public key not found at {PUBLIC_KEY_PATH}")

with open(PUBLIC_KEY_PATH, "rb") as f:
    pem_data = f.read()
    public_key = serialization.load_pem_public_key(pem_data)

# ---- Helper: RSA Encrypt using PKCS#1 v1.5 ----
def encrypt_with_ibm_key(plain_text: str) -> str:
    ciphertext = public_key.encrypt(
        plain_text.encode("utf-8"),
        padding.PKCS1v15()
    )
    return base64.b64encode(ciphertext).decode("utf-8")

# ---- Helper: IBM API Caller ----
def call_ibm_api(url: str, xhash: str, body: dict):
    headers = {
        "X-Hash-Value": xhash,
        "X-IBM-Client-Id": IBM_CLIENT_ID,
        "X-IBM-Client-Secret": IBM_CLIENT_SECRET,
        "X-Channel": X_CHANNEL,
        "Content-Type": "application/json",
        "accept": "application/json",
    }
    try:
        resp = requests.post(url, headers=headers, json=body, timeout=30)
        try:
            return resp.json()
        except Exception:
            return {"http_status": resp.status_code, "text": resp.text}
    except Exception as e:
        return {"error": str(e)}

# ---- (Optional) Additional permissive CORS headers for preflight handled here too ----
@app.after_request
def add_cors_headers(response):
    # Note: Flask-Cors already sets these; we keep these for compatibility.
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, X-Hash-Value, X-IBM-Client-Id, X-IBM-Client-Secret, X-Channel"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    return response

# ---- Global Storage ----
global_xhash = None

# ---- API: /api/encrypt ----
@app.route("/api/encrypt", methods=["POST"])
def api_encrypt():
    """
    Receives JSON: { number: "...", pin: "..." }
    Performs RSA encrypt (number:pin) -> calls IBM CorporateLogin -> if success, sets global_xhash and calls multiple IBM APIs.
    Returns encrypted value, login result, xHash and additional api results.
    """
    global global_xhash
    try:
        data = request.get_json(force=True)
        number = data.get("number")
        pin = data.get("pin")
        if not number or not pin:
            return jsonify({"error": "number and pin required"}), 400

        # Create payload and encrypt
        payload = f"{number}:{pin}"
        encrypted_value = encrypt_with_ibm_key(payload)

        # Corporate login
        login_url = "https://rgw.8798-f464fa20.eu-de.ri1.apiconnect.appdomain.cloud/tmfb/dev-catalog/CorporateLogin/"
        login_headers = {
            "X-IBM-Client-Id": IBM_CLIENT_ID,
            "X-IBM-Client-Secret": IBM_CLIENT_SECRET,
            "X-Channel": X_CHANNEL,
            "Content-Type": "application/json",
        }
        login_resp = requests.post(login_url, headers=login_headers, json={"LoginPayload": encrypted_value}, timeout=30)
        try:
            login_result = login_resp.json()
        except Exception:
            login_result = {"http_status": login_resp.status_code, "text": login_resp.text}

        additional_apis = {}

        # If login success -> set xhash and call all IBM APIs you had in original code
        if isinstance(login_result, dict) and login_result.get("ResponseCode") == "0":
            user_ts = f"{login_result.get('User')}~{login_result.get('Timestamp')}"
            global_xhash = encrypt_with_ibm_key(user_ts)
            xhash = global_xhash

            # Keep all API calls from your previous code — exact endpoints and request bodies preserved.
            additional_apis["MaToMATransfer"] = call_ibm_api(
                "https://rgw.8798-f464fa20.eu-de.ri1.apiconnect.appdomain.cloud/tmfb/dev-catalog/MaToMA/Transfer",
                xhash,
                {"Amount": "10", "MSISDN": number, "ReceiverMSISDN": "923355923388"}
            )

            additional_apis["MaToMAInquiry"] = call_ibm_api(
                "https://rgw.8798-f464fa20.eu-de.ri1.apiconnect.appdomain.cloud/tmfb/dev-catalog/MaToMA/Inquiry",
                xhash,
                {"Amount": "20", "MSISDN": number, "ReceiverMSISDN": "923355923388", "cnic": "3700448243372"}
            )

            additional_apis["SubscriberIBFTTransfer"] = call_ibm_api(
                "https://rgw.8798-f464fa20.eu-de.ri1.apiconnect.appdomain.cloud/tmfb/dev-catalog/SubscriberIBFT/Transfer",
                xhash,
                {
                    "Amount": "47",
                    "BankShortName": "MOD",
                    "BankTitle": "MOD",
                    "Branch": "00",
                    "AccountNumber": "00020000011005325",
                    "MSISDN": number,
                    "ReceiverMSISDN": "923332810960",
                    "ReceiverIBAN": "",
                    "SenderName": "ZEESHAN AHMED",
                    "TransactionPurpose": "0350",
                    "Username": "ZEESHAN AHMED"
                }
            )

            additional_apis["SubscriberIBFTInquiry"] = call_ibm_api(
                "https://rgw.8798-f464fa20.eu-de.ri1.apiconnect.appdomain.cloud/tmfb/dev-catalog/SubscriberIBFT/Inquiry",
                xhash,
                {
                    "Amount": "47",
                    "BankShortName": "MOD",
                    "BankTitle": "MOD",
                    "AccountNumber": "00020000011005325",
                    "MSISDN": number,
                    "ReceiverMSISDN": "923332810960",
                    "ReceiverIBAN": "923332810960",
                    "TransactionPurpose": "0350"
                }
            )

            additional_apis["MAtoCNICTransfer"] = call_ibm_api(
                "https://rgw.8798-f464fa20.eu-de.ri1.apiconnect.appdomain.cloud/tmfb/dev-catalog/MAtoCNIC/Transfer",
                xhash,
                {"Amount": "15", "MSISDN": number, "ReceiverMSISDN": "923482665224", "ReceiverCNIC": "3520207345019"}
            )

            additional_apis["MAtoCNICInquiry"] = call_ibm_api(
                "https://rgw.8798-f464fa20.eu-de.ri1.apiconnect.appdomain.cloud/tmfb/dev-catalog/MAtoCNIC/Inquiry",
                xhash,
                {"Amount": "15", "MSISDN": number, "ReceiverMSISDN": number, "ReceiverCNIC": "3520207345019"}
            )

            additional_apis["MaToMerchantTransfer"] = call_ibm_api(
                "https://rgw.8798-f464fa20.eu-de.ri1.apiconnect.appdomain.cloud/tmfb/dev-catalog/matomerchant/transfer",
                xhash,
                {
                    "Amount": "10.00",
                    "QuoteId": "1438964",
                    "MSISDN": number,
                    "MPOS": "923482665224",
                    "ReceiverMsisdn": "923482665224"
                }
            )

            additional_apis["MaToMerchantInquiry"] = call_ibm_api(
                "https://rgw.8798-f464fa20.eu-de.ri1.apiconnect.appdomain.cloud/tmfb/dev-catalog/matomerchant/inquiry",
                xhash,
                {
                    "Amount": "10.00",
                    "MSISDN": number,
                    "MPOS": "923482665224",
                    "ReceiverMsisdn": "923482665224"
                }
            )

            additional_apis["SubscriberUBPTransfer"] = call_ibm_api(
                "https://rgw.8798-f464fa20.eu-de.ri1.apiconnect.appdomain.cloud/tmfb/dev-catalog/SubscriberUtilityBill/Payment",
                xhash,
                {"Amount": "100.00", "ConsumerNumber": "01261110004080", "MSISDN": number, "Company": "PESCO"}
            )

            additional_apis["SubscriberUBPInquiry"] = call_ibm_api(
                "https://rgw.8798-f464fa20.eu-de.ri1.apiconnect.appdomain.cloud/tmfb/dev-catalog/SubscriberUtilityBill/Inquiry",
                xhash,
                {"ConsumerNumber": "01261110004080", "MSISDN": number, "Company": "PESCO"}
            )

            additional_apis["AccountLimitKYC"] = call_ibm_api(
                "https://rgw.8798-f464fa20.eu-de.ri1.apiconnect.appdomain.cloud/tmfb/dev-catalog/accountlimit_kyc/AccountLimitKYC",
                xhash,
                {
                    "msisdn": number,
                    "basicinfo": "true",
                    "additionalinfo": "true",
                    "personalinfo": "true",
                    "address": "true",
                    "cnic": "true",
                    "account": "true",
                    "email": "true",
                    "aml": "true",
                    "expirydate": "true"
                }
            )

            additional_apis["AccountBalance"] = call_ibm_api(
                "https://rgw.8798-f464fa20.eu-de.ri1.apiconnect.appdomain.cloud/tmfb/dev-catalog/account-balance/account-bal",
                xhash,
                {"msisdn": number}
            )

        # Return everything
        return jsonify({
            "encryptedValue": encrypted_value,
            "ibmLoginResult": login_result,
            "xHash": global_xhash,
            "additionalApis": additional_apis
        })

    except Exception as e:
        app.logger.exception("Encryption or IBM API call failed")
        return jsonify({"error": "Encryption or IBM API call failed", "details": str(e)}), 500


# ---- API: /api/inquire-transaction-status ----
@app.route("/api/inquire-transaction-status", methods=["POST"])
def inquire_transaction_status():
    global global_xhash
    try:
        data = request.get_json(force=True)
        transaction_id = data.get("transactionID")
        if not global_xhash:
            return jsonify({"error": "X-Hash not available. Please perform login first."}), 401
        if not transaction_id:
            return jsonify({"error": "transactionID is required."}), 400

        url = "https://rgw.8798-f464fa20.eu-de.ri1.apiconnect.appdomain.cloud/tmfb/dev-catalog/transaction-status-inquiry/TransactionStatusInquiry"

        headers = {
            "X-Hash-Value": global_xhash,
            "X-IBM-Client-Id": IBM_CLIENT_ID,
            "X-IBM-Client-Secret": IBM_CLIENT_SECRET,
            "accept": "application/json",
            "content-type": "application/json",
            "X-Channel": X_CHANNEL
        }
        payload = {"transactionID": transaction_id}

        resp = requests.post(url, headers=headers, json=payload, timeout=30)
        try:
            result = resp.json()
        except Exception:
            result = {"http_status": resp.status_code, "text": resp.text}

        return jsonify({"transactionStatusResult": result})

    except Exception as e:
        app.logger.exception("Transaction Status Inquiry failed")
        return jsonify({"error": "Transaction Status Inquiry failed", "details": str(e)}), 500


# ---- Serve index.html directly (dashboard) ----
@app.route("/")
def serve_index():
    # The dashboard HTML is intentionally long; using relative fetch URLs so remote users call this server (not their localhost)
    html = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>IBM/RSA API Dashboard</title>
<style>
  /* ---------- Global Styles ---------- */
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    background-color: #f4f7f9;
    color: #333;
    line-height: 1.6;
  }
  .container {
    max-width: 1000px;
    margin: 40px auto;
    padding: 20px;
  }
  h1, h2, h3 {
    color: #222;
  }
  h1 { text-align: center; margin-bottom: 30px; }

  /* ---------- Card Sections ---------- */
  .card {
    background: #fff;
    border-radius: 12px;
    padding: 25px 20px;
    margin-bottom: 25px;
    box-shadow: 0 8px 20px rgba(0,0,0,0.08);
    transition: transform 0.2s;
  }
  .card:hover { transform: translateY(-3px); }
  .card h3 { margin-bottom: 15px; }

  /* ---------- Form Styles ---------- */
  label { font-weight: 600; margin-bottom: 5px; display: block; color: #555; }
  input, select, button, textarea {
    width: 100%;
    padding: 12px;
    margin-bottom: 15px;
    border-radius: 8px;
    border: 1px solid #ccc;
    font-size: 14px;
  }
  input:focus, select:focus, textarea:focus { outline: none; border-color: #4a90e2; }
  button {
    background-color: #4a90e2;
    color: white;
    border: none;
    font-weight: 600;
    cursor: pointer;
    transition: 0.2s;
  }
  button:hover { background-color: #357ABD; }

  /* ---------- Response Boxes ---------- */
  .response-box {
    background: #f0f4ff;
    padding: 15px;
    border-radius: 10px;
    margin-top: 10px;
    overflow-x: auto;
  }
  .response-box h4 {
    margin-bottom: 8px;
    font-size: 16px;
    color: #222;
  }
  pre {
    font-family: monospace;
    font-size: 13px;
    white-space: pre-wrap;
    word-break: break-word;
    color: #111;
  }

  /* ---------- Transactions Table ---------- */
  table {
    width: 100%;
    border-collapse: collapse;
    margin-top: 10px;
    font-size: 14px;
  }
  th, td {
    padding: 8px 10px;
    border: 1px solid #ddd;
    text-align: left;
  }
  th {
    background-color: #4a90e2;
    color: white;
  }

  /* ---------- Responsive ---------- */
  @media (max-width: 600px) {
    .container { padding: 10px; }
  }
</style>
</head>
<body>
<div class="container">
  <h1>🔐 IBM/RSA API Dashboard</h1>

  <!-- ---------- Login Section ---------- -->
  <div class="card">
    <h3>1️⃣ Login & Generate X-Hash</h3>
    <label for="numberInput">Number</label>
    <select id="numberInput">
      <option value="923319154345">923319154345</option>
      <option value="923481565391">923481565391</option>
    </select>

    <label for="pinInput">PIN</label>
    <input type="password" id="pinInput" placeholder="Enter PIN">

    <button id="loginBtn">Encrypt & Login</button>

    <div id="loginResults" class="response-box" style="display:none;">
      <h4>Encrypted Value</h4>
      <textarea id="encryptedValue" rows="2" readonly></textarea>

      <h4>X-Hash</h4>
      <textarea id="xHash" rows="2" readonly></textarea>
    </div>
  </div>

  <!-- ---------- API Responses ---------- -->
  <div class="card" id="apiResponses" style="display:none;">
    <h3>2️⃣ API Responses</h3>
    <div id="allApiResponses"></div>
  </div>

  <!-- ---------- Transaction Status Inquiry ---------- -->
  <div class="card" id="transactionSection" style="display:none;">
    <h3>3️⃣ Transaction Status Inquiry</h3>
    <label for="transactionIdInput">Transaction ID</label>
    <input type="text" id="transactionIdInput" placeholder="Enter Transaction ID">
    <button id="transactionBtn">Check Status</button>

    <div id="transactionResult" class="response-box" style="display:none;">
      <h4>Transaction Status Result</h4>
      <pre id="transactionJSON"></pre>
      <div id="transactionsTableContainer"></div>
    </div>
  </div>
</div>

<script>
  // Use relative paths so remote users call the server that served the page
  const apiBase = ""; // empty -> use relative paths like "/api/encrypt"

  let xHashGlobal = "";

  function setLoading(button, state) {
    if(state){
      button.disabled = true;
      button.textContent = "Processing...";
    } else {
      button.disabled = false;
      button.textContent = button.getAttribute("data-original") || "Submit";
    }
  }

  // Login & API calls
  const loginBtn = document.getElementById("loginBtn");
  loginBtn.setAttribute("data-original", loginBtn.textContent);
  loginBtn.addEventListener("click", async () => {
    const number = document.getElementById("numberInput").value;
    const pin = document.getElementById("pinInput").value;
    if (!pin) { alert("Enter PIN"); return; }

    setLoading(loginBtn, true);

    try {
      const res = await fetch(`/api/encrypt`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ number, pin })
      });
      const data = await res.json();
      if(data.error) { throw new Error(data.error); }

      document.getElementById("encryptedValue").value = data.encryptedValue || "";
      document.getElementById("xHash").value = data.xHash || "";
      xHashGlobal = data.xHash || "";

      document.getElementById("loginResults").style.display = "block";
      document.getElementById("transactionSection").style.display = "block";

      // Display all API responses
      const apiContainer = document.getElementById("allApiResponses");
      apiContainer.innerHTML = "";
      const additionalApis = data.additionalApis || {};
      Object.keys(additionalApis).forEach(key => {
        const div = document.createElement("div");
        div.className = "response-box";
        div.innerHTML = `<h4>${key}</h4><pre>${JSON.stringify(additionalApis[key], null, 2)}</pre>`;
        apiContainer.appendChild(div);
      });
      document.getElementById("apiResponses").style.display = "block";

    } catch (err) {
      console.error("Login/API error:", err);
      alert("Login/API error: " + err.message);
    } finally {
      setLoading(loginBtn, false);
    }
  });

  // Transaction Status Inquiry
  const transactionBtn = document.getElementById("transactionBtn");
  transactionBtn.setAttribute("data-original", transactionBtn.textContent);
  transactionBtn.addEventListener("click", async () => {
    const transactionID = document.getElementById("transactionIdInput").value;
    if (!transactionID) { alert("Enter Transaction ID"); return; }
    if (!xHashGlobal) { alert("Perform login first"); return; }

    setLoading(transactionBtn, true);
    document.getElementById("transactionResult").style.display = "block";
    document.getElementById("transactionJSON").textContent = "Processing...";

    try {
      const res = await fetch(`/api/inquire-transaction-status`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ transactionID })
      });
      const data = await res.json();
      if(data.error) { throw new Error(data.error); }

      document.getElementById("transactionJSON").textContent = JSON.stringify(data.transactionStatusResult, null, 2);

      // Display transactions in table if exists
      const container = document.getElementById("transactionsTableContainer");
      container.innerHTML = "";
      const txs = (data.transactionStatusResult && data.transactionStatusResult.get && data.transactionStatusResult.get('transactions')) || data.transactionStatusResult.transactions;
      // above line tries to handle varying response shapes; fallback to `.transactions`
      if(txs && Array.isArray(txs)){
        let tableHTML = `<table><tr><th>Type</th><th>Amount</th></tr>`;
        txs.forEach(t => { tableHTML += `<tr><td>${t.transactionType}</td><td>${t.amount}</td></tr>`; });
        tableHTML += `</table>`;
        container.innerHTML = tableHTML;
      }

    } catch (err) {
      console.error("Transaction Status Inquiry error:", err);
      document.getElementById("transactionJSON").textContent = "Error: " + err.message;
    } finally {
      setLoading(transactionBtn, false);
    }
  });
</script>
</body>
</html>
"""
    resp = make_response(html)
    resp.headers["Content-Type"] = "text/html"
    return resp


# ---- Run ----
if __name__ == "__main__":
    debug_mode = os.environ.get("FLASK_DEBUG", "True").lower() in ("1", "true", "yes")
    app.run(port=int(os.environ.get("PORT", 5040)), host="0.0.0.0", debug=debug_mode)
