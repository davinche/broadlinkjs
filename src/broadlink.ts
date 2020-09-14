export enum SecurityMode {
  None,
  WEP,
  WPA1,
  WPA2,
}

export function Setup(ssid: string, password: string, securityMode: SecurityMode) : Buffer{
  const packet: Buffer = Buffer.alloc(136, 0);
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
  return packet;
}

function checksum(b: Buffer) : number{
  let cs = 0xbeaf;
  for (let i = 0; i < b.length; i++) {
    cs += b[i];
    cs = cs & 0xffff;
  }
  return cs;
}
