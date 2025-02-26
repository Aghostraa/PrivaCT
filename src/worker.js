import init, { LightClientWorker } from '../pkg/prism_wasm_lightclient.js';

Error.stackTraceLimit = 99;

await init();
console.log("Starting LightClientWorker");

let worker = await new LightClientWorker(self, "custom", "events-channel");

console.log(worker);

self.onmessage = (event) => {
    console.log("Worker received message:", event.data);
};

// delete this function
self.onmessage = function (event) {
    console.log("[WORKER RECEIVED]:", event.data);
  };
// delete this function
  self.postMessage = function (msg) {
    console.log("[WORKER SENT]:", msg);
  };
  

await worker.run();
