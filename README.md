# Prism Certificate Transparency Browser Extension

Trust-minimized Certificate Transparency checks using Prism

### Browser compatibility
- Firefox ≥109 ✅ (extension manifest v3)
- Chrome ❌ (no ETA)

## Development setup

### Requirements
- [Nodejs][nodejs]
- [Web-ext CLI][webext] (for Firefox)

### Install Dependencies
In the project directory

    npm install

### Run full node and CT-Service

git clone https://github.com/deltadevsde/prism-service-example
    cd prism-service-example
    cargo run
    

### Running the extension
Build the extension with

    npm run build

In the ```/dist``` folder, run

    web-ext run --devtools

## Roadmap

- [ ] Connection to prism CT-service
- [ ] Browser extension runs a prism light node
- [ ] Support Chrome based browsers (requires workaround to overcome lack of
      [getSecurityInfo()][getsecurityinfo])


[nodejs]: https://nodejs.org/
[webext]: https://github.com/mozilla/web-ext/
[getsecurityinfo]: https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/API/webRequest/getSecurityInfo
