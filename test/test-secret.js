import expect from "expect.js";
import {Secret} from "@zingle/secret";

describe("Secret", () => {
  describe("new (secret, {algoHMAC, algoJWT})", () => {
    const algoHMAC = "sha256";
    const algoJWT = "HS384";
    let secret;

    beforeEach(() => {
      secret = new Secret("sekret", {algoHMAC, algoJWT});
    });

    it("should initialize Secret object", () => {
      expect(secret.algoHMAC).to.be(algoHMAC);
      expect(secret.algoJWT).to.be(algoJWT);
    });

    it("should not expose secret", () => {
      expect(secret.secret).to.be(undefined);
    });

    it("should set default algorithms", () => {
      secret = new Secret("sekret");
      expect(secret.algoHMAC).to.be.a("string");
      expect(secret.algoJWT).to.be.a("string");
    });
  });

  describe(".signMessage(message)", () => {
    let secret;

    beforeEach(() => {
      secret = new Secret("sekret");
    });

    it("should accept string or Buffer", () => {
      expect(() => secret.signMessage("foo")).to.not.throwError();
      expect(() => secret.signMessage(Buffer.alloc(0))).to.not.throwError();
    });

    it("should return type matching argument", () => {
      expect(secret.signMessage("foo")).to.be.a("string");
      expect(secret.signMessage(Buffer.alloc(0))).to.be.a(Buffer);
    });

    it("should return value starting with original message", () => {
      expect(secret.signMessage("foo")).to.not.be("foo");
      expect(secret.signMessage("foo").startsWith("foo")).to.be(true);

      const buffer = Buffer.from("foo");

      expect(secret.signMessage(buffer).length).to.be.greaterThan(buffer.length);
      expect(secret.signMessage(buffer).slice(0,3).toString()).to.be("foo");
    });
  });

  describe(".verifyMessage(signedMessage)", () => {
    let secret;

    beforeEach(() => {
      secret = new Secret("sekret");
    });

    it("should return original message", () => {
      const signed = secret.signMessage("foo");
      expect(secret.verifyMessage(signed)).to.be("foo");
    });

    it("should return false if message could not be verified", () => {
      expect(secret.verifyMessage("fooXXX")).to.be(false);
    });
  });

  describe(".issueToken()", () => {
    let secret;

    beforeEach(() => {
      secret = new Secret("sekret");
    });

    it("should return JWT token", () => {
      expect(secret.issueToken()).to.be.a("string");
      expect(secret.issueToken()).to.not.be(secret.issueToken());
    });
  });

  describe(".verifyToken(token)", () => {
    let secret;

    beforeEach(() => {
      secret = new Secret("sekret");
    });

    it("should return token claims and payload", () => {
      const token = secret.issueToken({foo: "bar"});
      const detail = secret.verifyToken(token);

      expect(detail).to.be.an("object");
      expect(detail.aud).to.be.a("string");
      expect(detail.iss).to.be.a("string");
      expect(detail.exp).to.be.a("number");
      expect(detail.foo).to.be("bar");
    });
  });
});
