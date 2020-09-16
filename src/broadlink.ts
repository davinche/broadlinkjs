import * as dgram from "dgram";
import * as crypto from "crypto";
import { StreamController } from "tricklejs";
import { networkInterfaces } from "os";

export enum SecurityMode {
  None,
  WEP,
  WPA1,
  WPA2,
  WPA1or2,
}

export function Setup(ssid: string, password: string, securityMode: SecurityMode): Promise<void> {
  return new Promise(function (resolve, reject) {
    const socket = dgram.createSocket({
      type: "udp4",
      reuseAddr: true,
    });
    socket.on("listening", function () {
      socket.setBroadcast(true);
      const packet = Buffer.alloc(136, 0);
      packet.writeUInt8(0x14, 0x26);
      for (let i = 0; i < ssid.length; i++) {
        packet.writeUInt8(ssid[i].charCodeAt(0), 0x44 + i);
      }

      for (let i = 0; i < password.length; i++) {
        packet.writeUInt8(password[i].charCodeAt(0), 0x64 + i);
      }

      packet.writeUInt8(ssid.length, 0x84);
      packet.writeUInt8(password.length, 0x85);
      packet.writeUInt8(securityMode, 0x86);
      packet.writeUInt16LE(checksum(packet), 0x20);

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
    const now = new Date();
    const packet = Buffer.alloc(48, 0);
    const port = socket.address().port;
    packet.writeUInt32LE((now.getTimezoneOffset() / -60) & 0xffff, 0x8);
    packet.writeUInt16LE(now.getFullYear(), 0xc);
    packet.writeUInt8(now.getMinutes(), 0x0e);
    packet.writeUInt8(now.getHours(), 0x0f);
    packet.writeUInt8(now.getFullYear() % 100, 0x10);
    packet.writeUInt8(now.getDay(), 0x11);
    packet.writeUInt8(now.getDate(), 0x12);
    packet.writeUInt8(now.getMonth() + 1, 0x13);

    if (!localIP) {
      const ni = networkInterfaces();
      const ips: Array<string> = Object.keys(ni).reduce((ips: Array<string>, name) => {
        const net = ni[name];
        return ips.concat(net!.filter((n) => n.family === "IPv4" && !n.internal).map((n) => n.address));
      }, []);
      localIP = ips[0];
    }

    localIP
      .split(".")
      .map((part) => parseInt(part, 10))
      .forEach((part, idx) => packet.writeUInt8(part, 0x18 + idx));

    packet.writeUInt16LE(port, 0x1c);
    packet.writeUInt8(6, 0x26);
    packet.writeUInt16LE(checksum(packet), 0x20);
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
  _mac: Buffer;
  constructor(private _deviceType: number, _mac: Buffer | string, private _host: string, private _port: number) {
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
    if (typeof _mac === "string") {
      this._mac = Buffer.from(
        _mac
          .split(":")
          .map((part) => parseInt(part, 16))
          .reverse()
      );
    } else {
      this._mac = _mac;
    }
  }

  private _auth(): Promise<void> {
    if (this._authed) return Promise.resolve();
    return new Promise(async (resolve, reject) => {
      // prepare packet
      const payload = Buffer.alloc(80, 0);
      payload.writeUInt8(1, 0x1e);
      payload.writeUInt8(1, 0x2d);
      const mac = this.macAddress;
      Buffer.from(`===${mac.split(":").join("")}`, "utf8").copy(payload, 4, 0);
      Buffer.from(mac).copy(payload, 0x30, 0);
      const packet = this._getPacket(0x65, payload);

      // get auth keys
      const data = await this._sendPacket(packet);
      try {
        this._checkError(data);
        const decipher = crypto.createDecipheriv("aes-128-cbc", this._key, this._iv);
        decipher.setAutoPadding(false);
        const deciphered = Buffer.concat([decipher.update(data.slice(0x38)), decipher.final()]);
        this._id = deciphered.slice(0, 4);
        this._key = deciphered.slice(4, 0x14);
        this._authed = true;
        resolve();
      } catch (e) {
        reject(e);
      }
    });
  }

  private _getPacket(command: number, payload: Buffer): Buffer {
    const header = Buffer.alloc(56, 0);
    const staticHeader = Buffer.from([0x5a, 0xa5, 0xaa, 0x55, 0x5a, 0xa5, 0xaa, 0x55]);
    this._count = (this._count + 1) & 0xffff;
    staticHeader.copy(header, 0, 0);
    header.writeUInt16LE(this._deviceType, 0x24);
    header.writeUInt16LE(command, 0x26);
    header.writeUInt16LE(this._count, 0x28);
    this._mac.copy(header, 0x2a, 0);
    this._id.copy(header, 0x30, 0);
    header.writeUInt16LE(checksum(payload), 0x34);

    // checksum
    const packet = Buffer.concat([header, this.encrypt(payload)]);
    packet.writeUInt16LE(checksum(packet), 0x20);
    return packet;
  }

  private _sendPacket(packet: Buffer): Promise<Buffer> {
    return new Promise((resolve, reject) => {
      const socket = dgram.createSocket({
        type: "udp4",
        reuseAddr: true,
      });
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

  private _checkError(data: Buffer) {
    if (data.length < 48) {
      throw new Error("invalid length");
    }

    const cs = data.readUInt16LE(0x20);
    data.writeUInt16LE(0, 0x20);
    if (checksum(data) !== cs) {
      throw new Error("checksum error");
    }

    const ecode = data.readUInt16LE(0x22);
    if (ecode) {
      throw new Error(`error: code= ${ecode}`);
    }
  }

  encrypt(data: Buffer): Buffer {
    const encryptor = crypto.createCipheriv("aes-128-cbc", this._key, this._iv);
    encryptor.setAutoPadding(false);
    data = Buffer.concat([data, Buffer.alloc(16 - (data.length % 16), 0)]);
    return Buffer.concat([encryptor.update(data), encryptor.final()]);
  }

  decrypt(encrypted: Buffer): Buffer {
    const decryptor = crypto.createDecipheriv("aes-128-cbc", this._key, this._iv);
    decryptor.setAutoPadding(false);
    return Buffer.concat([decryptor.update(encrypted), decryptor.final()]);
  }

  enterLearning(): Promise<void> {
    return new Promise(async (resolve) => {
      await this._auth();
      const payload = Buffer.alloc(16, 0);
      payload[0] = 3;
      const packet = this._getPacket(0x6a, payload);
      await this._sendPacket(packet);
      resolve();
    });
  }

  checkData(): Promise<Buffer> {
    return new Promise(async (resolve, reject) => {
      try {
        await this._auth();
        const payload = Buffer.alloc(16, 0);
        payload[0] = 4;
        const packet = this._getPacket(0x6a, payload);
        const response = await this._sendPacket(packet);
        this._checkError(response);
        const data = this.decrypt(response.slice(0x38)).slice(4);
        resolve(data);
      } catch (e) {
        reject(e);
      }
    });
  }

  sendData(d: Buffer): Promise<void> {
    return new Promise(async (resolve) => {
      await this._auth();
      const header = Buffer.from([2, 0, 0, 0]);
      const payload = Buffer.concat([header, d]);
      const packet = this._getPacket(0x6a, payload);
      await this._sendPacket(packet);
      resolve();
    });
  }

  checkTemperature(): Promise<number> {
    return new Promise(async (resolve, reject) => {
      try {
        await this._auth();
        const payload = Buffer.from([1]);
        const packet = this._getPacket(0x6a, payload);
        const response = await this._sendPacket(packet);
        this._checkError(response);
        const data = this.decrypt(response.slice(0x38)).slice(4);
        resolve(data[0] + data[1] / 10.0);
      } catch (e) {
        reject(e);
      }
    });
  }

  get macAddress(): string {
    const pad = (s: string) => (s.length < 2 ? `0${s}` : s);
    return [this._mac[5], this._mac[4], this._mac[3], this._mac[2], this._mac[1], this._mac[0]]
      .map((b) => pad(b.toString(16)))
      .join(":");
  }

  get hostport(): string {
    return `${this._host}:${this._port}`;
  }
}

function checksum(b: Buffer): number {
  return b.reduce((cs, byte) => (cs + byte) & 0xffff, 0xbeaf);
}
