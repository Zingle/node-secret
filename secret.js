import {hostname} from "os";
import {createHmac, randomBytes} from "crypto";
import jwt from "jsonwebtoken";

export class Secret {
  #secret;
  #algoHMAC; #algoJWT;

  constructor(secret, {
    algoHMAC="sha1",
    algoJWT="HS256"
  }={}) {
    this.#secret = secret;
    this.#algoHMAC = algoHMAC;
    this.#algoJWT = algoJWT;
  }

  get algoHMAC() { return this.#algoHMAC; }
  get algoJWT() { return this.#algoJWT; }

  issueToken({aud, exp, iss, jti, nbf, sub, ...payload}) {
    const options = {algorithm: this.algoJWT};

    if (!iss) options.issuer = hostname();
    if (!aud) options.audience = hostname();
    if (!sub) options.subject = hostname();
    if (!exp) options.expiresIn = 300;    // seconds; 5 minutes
    if (!nbf) options.notBefore = 0;
    if (!jti) options.jwtid = randomBytes(8).toString("hex");

    return jwt.sign(payload, this.#secret, options);
  }

  signMessage(message) {
    const hmac = createHmac(this.algoHMAC, this.#secret);
    const digest = hmac.update(message).digest();
    const length = Buffer.from([digest.length]);
    const mac = Buffer.concat([digest, length]).toString("hex");

    if (message instanceof Buffer) {
      return Buffer.concat([message, Buffer.from(mac)]);
    } else {
      return message + mac;
    }
  }

  verifyMessage(signedMessage) {
    const hmac = createHmac(this.algoHMAC, this.#secret);
    const [data, mac] = signedMessage instanceof Buffer
      ? decodeMessageBuffer(signedMessage)
      : decodeMessageString(signedMessage);

    return hmac.update(data).digest("hex") === mac ? data : false;

    function decodeMessageBuffer(buffer) {
      const encodedLength = buffer.slice(-2).toString("ascii");       // hex
      const length = Buffer.from(encodedLength, "hex")[0];            // integer
      const mac = buffer.slice(-(2+length*2), -2).toString("ascii");  // hex
      const data = buffer.slice(0, -(2+length*2));
      return [data, mac];
    }

    function decodeMessageString(string) {
      const encodedLength = string.slice(-2);                         // hex
      const length = Buffer.from(encodedLength, "hex")[0];            // integer
      const mac = string.slice(-(2+length*2), -2);                    // hex
      const data = string.slice(0, -(2+length*2));
      return [data, mac];
    }
  }

  verifyToken(token, {age, aud, iss, sub}={}) {
    const options = {algorithms: [this.#algoJWT]};

    if (age) options.maxAge = age;
    if (aud) options.audience = aud;
    if (iss) options.issuer = iss;
    if (sub) options.subject = subject;

    return jwt.verify(token, this.#secret, options);
  }
}
