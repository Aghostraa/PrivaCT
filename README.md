# PrivaCT

PrivaCT is a Browser Extension which uses [Prism](https://www.prism.rs) to ensure Trust-minimized Certificate Transparency.

## Background 📖

When you visit a website, your browser establishes a secure connection using TLS certificates issued by trusted certificate authorities (CAs). These certificates prove that the site is authentic. However, certificate authorities have a history of being compromised or issuing certificates improperly. This can lead to man-in-the-middle attacks, phishing sites looking perfectly valid, or government surveillance programs abusing misissued certificates. To combat this, the concept of Certificate Transparency (CT) was introduced. The idea is that every certificate issued by a CA should be publicly logged in an append-only, tamper-proof transparency log. But there’s still a gap — as a user visiting a website, how do you know that the certificate you’re seeing has actually been properly logged in one of these transparency logs? That’s where this extension comes in.


## Goal 🎯

The purpose of this project is to enable everyday users to automatically and transparently check whether a website’s certificate is properly logged in the a Prism based transparency system — right from their browser. This brings the benefits of decentralized, trust-minimized certificate transparency directly to end users. 

## Architecture 🏛️

The system consists of three key components:

* A Prism devnet, which acts as a distributed, transparent store for certificates.
* A CT Service, which continuously fetches certificates from transparency logs and submits them to Prism.
* The Browser Extension, which is responsible for verifying certificates directly against the Prism devnet whenever the user visits a website.

## Browser Extension Workflow ⚙️⚙

1. When the user navigates to a website, the extension triggers a background check that extracts the site’s TLS certificate using an API in Firefox.
1. Queries the Prism Full Node to retrieve a Merkle Proof for the certificate  
1. Fetches the latest root hash from Prism to ensure it’s working with an up-to-date view of the transparency log.
1. Verifies the proof using an inclusion proof directly inside the extension.
1. Validates both the Merkle proof from the CA as well as from prism
1. Finally, it updates the browser action icon — green if the certificate is valid and logged, red if the certificate fails the check or is missing.

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

To run the browser extension it is necessary to run a Prism full node locally. This can be done using the following steps:

```sh
    git clone https://github.com/deltadevsde/prism-service-example
```
```sh
    cd prism-service-example
```
```sh
    cargo run
```

Next we need to run a service which fetches CT logs and puts them in Prism. This can be done by using the following commands:

```sh
    git clone https://github.com/MmithridatesS/ct-service-v2.git
```
```sh
    cd ct-service-v2
```
```sh
    cargo run
```

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
    web-ext run --devtools
```

[nodejs]: https://nodejs.org/
[webext]: https://github.com/mozilla/web-ext/
[rust]: https://www.rust-lang.org

