import * as dgram from "dgram";
import * as crypto from "crypto";
import { StreamController } from "tricklejs";
import { networkInterfaces } from "os";

export enum SecurityMode {
  None,
  WEP,
  WPA1,
  WPA2,
  WPA1Or2,
}

export function Setup(ssid: string, password: string, securityMode: SecurityMode): Promise<void> {
  return new Promise(function (resolve, reject) {
    const socket = dgram.createSocket({ type: "udp4", reuseAddr: true });
    socket.on("listening", function () {
      socket.setBroadcast(true);
      const packet = Buffer.alloc(136, 0);
      packet[0x26] = 0x14;
      for (let i = 0; i < ssid.length; i++) {
        packet[0x44 + i] = ssid[i].charCodeAt(0);
      }
      for (let i = 0; i < password.length; i++) {
        packet[0x64 + i] = password[i].charCodeAt(0);
      }
      packet[0x84] = ssid.length;
      packet[0x85] = password.length;
      packet[0x85] = securityMode;
      let cs = checksum(packet);
      packet[0x20] = cs & 0xff;
      packet[0x21] = cs >> 8;
      socket.send(packet, 80, "255.255.255.255", function (err) {
        if (err) {
          socket.close();
          return reject(err);
        }
        socket.close();
        resolve();
      });
    });
    socket.bind();
  });
}

export function Discover(timeout: number = 0, localIP?: string) {
  const sc = new StreamController<Device>();
  const socket = dgram.createSocket({ type: "udp4", reuseAddr: true });
  sc.onCancel = () => socket.close();

  socket.on("listening", function () {
    socket.setBroadcast(true);
    const packet = Buffer.alloc(48, 0);
    const now = new Date();
    const timezone = now.getTimezoneOffset() / -60;
    const year = now.getFullYear();
    const port = socket.address().port;

    if (timezone < 0) {
      packet[0x08] = 0xff + timezone - 1;
      packet[0x09] = 0xff;
      packet[0x0a] = 0xff;
      packet[0x0b] = 0xff;
    } else {
      packet[0x08] = timezone;
    }

    packet[0x0c] = year & 0xff;
    packet[0x0d] = year >> 8;
    packet[0x0e] = now.getMinutes();
    packet[0x0f] = now.getHours();
    packet[0x10] = year % 100;
    packet[0x11] = now.getDay();
    packet[0x12] = now.getDate();
    packet[0x13] = now.getMonth() + 1;
    if (!localIP) {
      const ni = networkInterfaces();
      const ips: Array<string> = Object.keys(ni).reduce((ips: Array<string>, name) => {
        const net = ni[name];
        return ips.concat(net!.filter((n) => n.family === "IPv4" && !n.internal).map((n) => n.address));
      }, []);
      localIP = ips[0];
    }
    const parsedIP: Array<number> = localIP.split(".").map((part) => parseInt(part, 10));
    [packet[0x18], packet[0x19], packet[0x1a], packet[0x1b]] = parsedIP;
    packet[0x1c] = port & 0xff;
    packet[0x1d] = port >> 8;
    packet[0x26] = 6;
    const cs = checksum(packet);
    packet[0x20] = cs & 0xff;
    packet[0x21] = cs >> 8;
    socket.send(packet, 0, packet.length, 80, "255.255.255.255", function (err) {
      if (err) {
        sc.addError(err);
      }
    });
  });

  socket.on("message", function (msg, rinfo) {
    const deviceType = msg[0x34] | (msg[0x35] << 8);
    const mac = msg.slice(0x3a, 0x40);
    const device = new Device(deviceType, mac, rinfo.address, rinfo.port);
    sc.add(device);
  });
  Promise.resolve().then(() => socket.bind());
  if (timeout) setTimeout(sc.close.bind(sc), timeout);
  return sc.stream;
}

export class Device {
  _count: number;
  _id: Buffer;
  _iv: Buffer;
  _key: Buffer;
  _authed = false;
  constructor(private _deviceType: number, private _mac: Buffer, private _host: string, private _port: number) {
    this._count = crypto.randomBytes(2).readUInt16BE();
    this._id = Buffer.alloc(4, 0);
    this._key = Buffer.from([
      0x09,
      0x76,
      0x28,
      0x34,
      0x3f,
      0xe9,
      0x9e,
      0x23,
      0x76,
      0x5c,
      0x15,
      0x13,
      0xac,
      0xcf,
      0x8b,
      0x02,
    ]);
    this._iv = Buffer.from([
      0x56,
      0x2e,
      0x17,
      0x99,
      0x6d,
      0x09,
      0x3d,
      0x28,
      0xdd,
      0xb3,
      0xba,
      0x69,
      0x5a,
      0x2e,
      0x6f,
      0x58,
    ]);
  }

  getPacket(command: number, payload: Buffer): Buffer {
    const header = Buffer.alloc(56, 0);
    this._count = (this._count + 1) & 0xffff;
    header[0x00] = 0x5a;
    header[0x01] = 0xa5;
    header[0x02] = 0xaa;
    header[0x03] = 0x55;
    header[0x04] = 0x5a;
    header[0x05] = 0xa5;
    header[0x06] = 0xaa;
    header[0x07] = 0x55;
    header[0x24] = this._deviceType & 0xff;
    header[0x25] = this._deviceType >> 8;
    header[0x26] = command;
    header[0x28] = this._count & 0xff;
    header[0x29] = this._count >> 8;
    header[0x2a] = this._mac[0];
    header[0x2b] = this._mac[1];
    header[0x2c] = this._mac[2];
    header[0x2d] = this._mac[3];
    header[0x2e] = this._mac[4];
    header[0x2f] = this._mac[5];
    header[0x30] = this._id[0];
    header[0x31] = this._id[1];
    header[0x32] = this._id[2];
    header[0x33] = this._id[3];

    let cs = checksum(payload);
    header[0x34] = cs & 0xff;
    header[0x35] = cs >> 8;

    const cipher = crypto.createCipheriv("aes-128-cbc", this._key, this._iv);
    cipher.setAutoPadding(false);
    const encryptedPayload = Buffer.concat([cipher.update(payload), cipher.final()]);
    const packet = Buffer.concat([header, encryptedPayload]);
    cs = checksum(packet);
    packet[0x20] = cs & 0xff;
    packet[0x21] = cs >> 8;
    return packet;
  }

  sendPacket(packet: Buffer): Promise<Buffer> {
    return new Promise((resolve, reject) => {
      const socket = dgram.createSocket({ type: "udp4", reuseAddr: true });
      socket.on("message", (data: Buffer) => {
        socket.close();
        resolve(data);
      });

      socket.on("listening", () => {
        socket.send(packet, this._port, this._host, function (err) {
          if (err) {
            socket.close();
            reject(err);
          }
        });
      });
      socket.bind();
    });
  }

  auth(): Promise<void> {
    if (this._authed) return Promise.resolve();
    return new Promise(async (resolve, reject) => {
      const payload = Buffer.alloc(80, 0);
      payload[0x1e] = 0x1;
      payload[0x2d] = 0x1;

      const mac = this.macAddress;
      Buffer.from(`===${mac.split(":").join("")}`, "utf8").copy(payload, 4, 0);
      Buffer.from(mac).copy(payload, 0x30, 0);
      const packet = this.getPacket(0x65, payload);
      const data = await this.sendPacket(packet);
      if (data.length < 48) {
        return reject(new Error('invalid length'));
      }

      const cs = data[0x20] | (data[0x21] << 8);
      const dataCS = checksum(data);
      if (((dataCS - data[0x20] - data[0x21]) & 0xffff) !== cs) {
        return reject(new Error('checksum error'));
      }

      const ecode = data[0x22] | (data[0x23] << 8);
      if (ecode) {
        return reject(new Error(`error: code= ${ecode}`));
      }

      const decipher = crypto.createDecipheriv("aes-128-cbc", this._key, this._iv);
      decipher.setAutoPadding(false);
      const deciphered = Buffer.concat([decipher.update(data.slice(0x38)), decipher.final()]);
      this._id = deciphered.slice(0, 4);
      this._key = deciphered.slice(4, 0x14);
      this._authed = true;
      resolve();
    });
  }

  enterLearning(): Promise<Buffer> {
    return new Promise(async (resolve) => {
      await this.auth();
      const payload = Buffer.alloc(16, 0);
      payload[0] = 3;
      const packet = this.getPacket(0x6a, payload);
      const data = await this.sendPacket(packet);
      console.log(data);
      resolve();
    });
  }

  get macAddress(): string {
    const pad = (s: string) => (s.length < 2 ? `0${s}` : s);
    return [this._mac[5], this._mac[4], this._mac[3], this._mac[2], this._mac[1], this._mac[0]]
      .map((b) => pad(b.toString(16)))
      .join(":");
  }
}

function checksum(b: Buffer): number {
  return b.reduce((cs, byte) => (cs + byte) & 0xffff, 0xbeaf);
}
