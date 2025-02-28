# PrivaCT

PrivaCT is a Browser Extension which uses Prism to ensure Trust-minimized Certificate Transparency.

### Browser compatibility
- Firefox ≥109 ✅ (extension manifest v3)

## Development setup

### Requirements
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
Once the Prism Full Node is running the user and the service has also been running for a while. The extension is ready to use,
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
