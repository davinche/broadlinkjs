#!/usr/bin/env node

import { Setup, SecurityMode, Discover, Device } from "./broadlink";
import prompts from "prompts";
import * as clipboardy from "clipboardy";

(async function () {
  const action = await prompts([
    {
      type: "select",
      name: "value",
      message: "What would you like to do?",
      choices: [
        { title: "Discover", value: "discover" },
        { title: "Setup", value: "setup" },
      ],
    },
  ]);
  switch (action.value) {
    case "discover":
      await discover();
      break;
    case "setup":
      await setup();
      break;
  }
})();

async function setup() {
  const response = await prompts([
    {
      type: "text",
      name: "ssid",
      message: "SSID?",
    },
    {
      type: "password",
      name: "password",
      message: "Password?",
    },
    {
      type: "select",
      name: "wireless",
      message: "Wireless?",
      choices: [
        {
          title: "None",
          value: SecurityMode.None,
        },
        {
          title: "WPA1",
          value: SecurityMode.WPA1,
        },
        {
          title: "WPA2",
          value: SecurityMode.WPA2,
        },
        {
          title: "WPA1/2",
          value: SecurityMode.WPA1or2,
        },
      ],
    },
  ]);
  try {
    await Setup(response.ssid, response.password, response.wireless);
  } catch (e) {
    console.error(`could not set up device: error=${e}`);
  }
}

async function discover() {
  const sleep = (s: number) => new Promise((resolve) => setTimeout(resolve, s * 1000));
  const response = await prompts([
    {
      type: "number",
      name: "secs",
      message: "Timeout (secs)",
      initial: 2,
    },
  ]);
  console.log("\nSearching...\n");
  try {
    let devices: Array<Device> = [];
    const stream = Discover(response.secs * 1000);
    stream.listen((device) => devices.push(device));
    await sleep(response.secs);
    if (!devices.length) {
      throw "no devices found";
    }

    const selectedDevice = await prompts([
      {
        type: "select",
        name: "value",
        message: "Which Device?",
        choices: devices.map((d) => {
          return {
            value: d,
            title: `${d.hostport} / ${d.macAddress}`,
          };
        }),
      },
    ]);

    const d = selectedDevice.value as Device;

    while (true) {
      const action = await prompts(
        [
          {
            type: "select",
            name: "value",
            message: "What to do?",
            choices: [
              {
                title: "Enter Learning Mode",
                value: "learn",
              },
              {
                title: "Read Learned Code",
                value: "read",
              },
              {
                title: "Send Code",
                value: "send",
              },
            ],
          },
        ],
        { onCancel: () => process.exit(0) }
      );

      try {
        switch (action.value) {
          case "learn":
            await d.enterLearning();
            break;
          case "read":
            const data = await d.checkData();
            const b64 = data.toString("base64");
            // copy(b64);
            clipboardy.write(b64);
            console.log("data:", b64, "copied to clipboard");
            break;
          case "send":
            const resp = await prompts([
              {
                type: "text",
                message: "Data?",
                name: "value",
              },
            ]);
            const b = Buffer.from(resp.value, "base64");
            await d.sendData(b);
            break;
        }
      } catch (e) {
        console.error(`could not perform action; action=${action.value}, error=${e}`);
      }
    }
  } catch (e) {
    console.error(`could not discover device: error=${e}`);
  }
}
