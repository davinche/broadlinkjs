Broadlink JS
============

- Partial (only RM2 support) port of
  <https://github.com/mjg59/python-broadlink>
- Both CLI / Lib included

## Installation

`npm install js-broadlink`


## Usage

- As CLI: `npx broadlink`
- As lib:

Example:

```javascript
import { Setup, SecurityMode, Discover } from "js-broadlink";
const sleep = (s: number) => new Promise((resolve) => setTimeout(resolve, s * 1000));

// discover
async function discover() {
  const devices = [];
  const stream = Discover(1000); // wait for 1 second before closing
  stream.listen((device) => devices.push(device));
  await sleep(1);
  
  if (devices.length) {
    // use device here
    await devices[0].enterLearning();
    // read, send code etc...
  }
}
```

or callback style


```javascript
import { Discover } from "js-broadlink";

// discover
function discover(callback) {
  const stream = Discover(); // wait indefinitely...
  const subscrption = stream.listen((device) => {
    subscription.cancel(); // cancels subscription after first device
    callback(device);
  });
}

async function myCallback(device) {
  await device.enterLearning();
  // read, send code etc...
}

discover(myCallback);
```
