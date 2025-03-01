# PrivaCT: Trust-Minimized Certificate Transparency  

**PrivaCT** is a browser extension that leverages **Prism** to deliver trust-minimized Certificate Transparency (CT) directly to users.  

---

## **Background** 📖  

When you visit a website, your browser establishes a secure connection using TLS certificates issued by trusted Certificate Authorities (CAs). These certificates verify the site’s authenticity. However, CAs have a history of being compromised or issuing certificates improperly, leading to risks like man-in-the-middle attacks, phishing sites appearing legitimate, or even government surveillance programs exploiting misissued certificates.  

To address these issues, **Certificate Transparency (CT)** was introduced. CT requires that every certificate issued by a CA be publicly logged in an append-only, tamper-proof transparency log. But here’s the catch: as a user, how do you know if the certificate you’re seeing has actually been logged in one of these transparency logs? This is where **PrivaCT** steps in.  

---

## **Goal** 🎯  

The goal of PrivaCT is to empower everyday users by automatically and transparently verifying whether a website’s certificate is properly logged in a **Prism-based transparency system** — all from within their browser. This brings the benefits of decentralized, trust-minimized certificate transparency directly to end users.  

---

## **Architecture** 🏛️  

The system is built on three core components:  

1. **Prism Devnet**: A distributed, transparent store for certificates.  
2. **CT Service**: Continuously fetches certificates from transparency logs and submits them to Prism.  
3. **Browser Extension**: Verifies certificates directly against the Prism Devnet whenever a user visits a website.  

---

## **Browser Extension Workflow** ⚙️  

Here’s how the extension works:  

1. When a user navigates to a website, the extension triggers a background check.  
2. It extracts the site’s TLS certificate using a Firefox API.  
3. The extension queries the **Prism Full Node** to retrieve a **Merkle Proof** for the certificate.  
4. It fetches the latest **root hash** from Prism to ensure it’s working with an up-to-date view of the transparency log.  
5. The extension verifies the proof using an **inclusion proof** directly within the browser.  
6. It validates both the **Merkle proof** from the CA and the proof from Prism.  
7. Finally, it updates the browser action icon:  
   - **Green**: The certificate is valid and logged.  
   - **Red**: The certificate fails the check or is missing.  

---

PrivaCT bridges the gap between Certificate Transparency and user trust, ensuring a safer and more transparent browsing experience.

## Development setup 👨‍💻

### Browser compatibility
- Firefox ≥109 ✅ (extension manifest v3)

### Requirements
- [Rust][rust]
- [Nodejs][nodejs]
- [Web-ext CLI][webext] (for Firefox)

### Install Dependencies
In the project directory
```sh
    npm install
```

### Run full node and CT-Service

Go to the following repo and follow the instructions given: https://github.com/MmithridatesS/PrivaCT-service

Once the service is run it needs some time to set up the accounts of CT log providers. In the real world scenario the service 
would be running in the backend, thereby freeing the user of these steps. 
    

### Running the extension
Once the Prism full node is running, and the service has also been running for a while. The extension is ready to use,
which can be done by using the following steps in the project directory:

```sh
    npm run build
```
```sh
    cd dist
```
```sh
    web-ext run
```

[nodejs]: https://nodejs.org/
[webext]: https://github.com/mozilla/web-ext/
[rust]: https://www.rust-lang.org

