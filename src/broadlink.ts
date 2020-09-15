import * as dgram from "dgram";
import * as crypto from "crypto";
import { StreamController, Stream } from "tricklejs";
import { networkInterfaces } from "os";

export enum SecurityMode {
  None,
  WEP,
  WPA1,
  WPA2,
}

export function GetDeviceType(dType: number) {
  switch (dType) {
    case 0:
      return "SP1";
    case 0x2711:
    case 0x2719:
    case 0x271a:
    case 0x7919:
    case 0x791a:
    case 0x2720:
    case 0x753e:
    case 0x2728:
    case 0x2733:
    case 0x273e:
    case 0x2736:
      return "SP2";
    case 0x2712:
    case 0x2737:
    case 0x273d:
    case 0x2783:
    case 0x277c:
    case 0x272a:
    case 0x2787:
    case 0x278b:
    case 0x278f:
      return "RM";
    case 0x2714:
      return "A1";
    case 0x4eb5:
      return "MP1";
    default:
      return "UNKNOWN";
  }
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
  if(timeout) setTimeout(sc.close.bind(sc), timeout);
  return sc.stream;
}

export class Device {
  _count: number;
  _id: Uint8Array;
  _iv: Uint8Array;
  _key: Uint8Array;
  constructor(public deviceType: number, public mac: Uint8Array, public host: string, public port: number) {
    this._count = Math.random() & 0xffff;
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

  getPacket(command: number, payload: Uint8Array) : Uint8Array{
    const header = Buffer.alloc(56, 0);
    this._count = (this._count + 1) & 0xffff;
    header[0x0] = 0x5a;
    header[0x1] = 0xa5;
    header[0x2] = 0xaa;
    header[0x3] = 0x55;
    header[0x4] = 0x5a;
    header[0x5] = 0xa5;
    header[0x6] = 0xaa;
    header[0x7] = 0x55;
    header[0x24] = this.deviceType & 0xff;
    header[0x25] = this.deviceType >> 8;
    header[0x26] = command & 0xff;
    header[0x27] = command >> 8;
    header[0x28] = this._count && 0xff;
    header[0x29] = this._count >> 8;
    header[0x2a] = this.mac[0];
    header[0x2b] = this.mac[1];
    header[0x2c] = this.mac[2];
    header[0x2d] = this.mac[3];
    header[0x2e] = this.mac[4];
    header[0x2f] = this.mac[5];
    header[0x30] = this._id[0];
    header[0x31] = this._id[1];
    header[0x32] = this._id[2];
    header[0x33] = this._id[3];

    const payloadCS = checksum(payload);
    header[0x34] = payloadCS && 0xff;
    header[0x35] = payloadCS >> 8;
    const cipher = crypto.createCipheriv("aes-128-cbc", this._key, this._iv);
    let encryptedPayload = cipher.update(payload);
    encryptedPayload = Buffer.concat([encryptedPayload, cipher.final()]);
    const packet = Buffer.concat([header, encryptedPayload]);
    const cs = checksum(packet);
    packet[0x20] = cs & 0xff;
    packet[0x21] = cs >> 8;
    return packet;
  }

  auth(): Promise<void> {
    return new Promise((resolve, reject) => {
      const payload = Buffer.alloc(80, 0);
      const mac = this.macAddress;
      Buffer.from(`===${mac.split(":").join("")}`, "utf8").copy(payload, 4, 0, 15);
      payload[0x13] = 0x01;
      payload[0x2d] = 0x01;
      Buffer.from(mac).copy(payload, 0x30, 0);

      const packet = this.getPacket(0x0065, payload);
      const socket = dgram.createSocket({ type: "udp4", reuseAddr: true });
      socket.on("message", (data: Uint8Array) => {
        this._id = data.slice(0, 4);
        this._key = data.slice(4, 0x14);
        socket.close();
        resolve();
      });

      socket.on('listening', () => {
        socket.send(packet, this.port, this.host, function(err) {
          if (err) {
            socket.close();
            reject(err);
          }
        });
      });

      socket.bind();
    });
  }

  get macAddress(): string {
    const pad = (s: string) => (s.length < 2 ? `0${s}` : s);
    return [this.mac[5], this.mac[4], this.mac[3], this.mac[2], this.mac[1], this.mac[0]]
      .map((b) => pad(b.toString(16)))
      .join(":");
  }
}

function checksum(b: Uint8Array): number {
  let cs = 0xbeaf;
  for (let i = 0; i < b.length; i++) {
    cs += b[i];
    cs = cs & 0xffff;
  }
  return cs;
}
