/*!
 * axfr.js - AXFR plugin for hsd
 * Copyright (c) 2021 Buffrr (MIT License).
 *
 * parts of this software are based on:
 * https://github.com/handshake-org/hsd
 * https://github.com/chjj/bns
 */

'use strict';

const net = require('net');
const bns = require('bns');
const IP = require('binet');

const {
  wire,
  util,
  dnssec
} = bns;

const {
  Message,
  types,
  opcodes,
  Question
} = wire;

const MAX_MESSAGE_SIZE = 65535;

class AXFRClient {
  constructor(options) {
    this.index = 0;
    this.maxAttempts = 6;
    this.maxTimeout = 6000;
    this.maxMessages = 1000;
    this.servers = null;
    this.parseOptions(options);
  }

  parseOptions(options) {
    if (options == null)
      return;

    assert(options && typeof options === 'object');

    if (options.servers != null) {
      this.servers = [];
      for (const server of options.servers)
        this.servers.push(IP.fromHost(server, 53));
    }

    if (options.logger != null)
      this.logger = options.logger;

    if (options.maxAttempts != null)
      this.maxAttempts = options.maxAttempts;

    if (options.maxTimeout != null)
      this.maxTimeout = options.maxTimeout;

    if (options.maxMessages)
      this.maxMessages = options.maxMessages;
  }

  async query(zone) {
    let server = this.getServer();

    for (let i = 0; i < this.maxAttempts; i++) {
      try {
        const q = new AXFRQuery({
          zone: zone,
          maxTimeout: this.maxTimeout,
          maxMessages: this.maxMessages
        });

        return await q.exchange(server.port, server.host);
      } catch (e) {
        this.logger.warning('Attempt [%s:%d] failed: %s',
          server.host, server.port, e.toString());

        server = this.nextServer();
      }
    }

    return null;
  }

  getServer() {
    return this.servers[this.index];
  }

  nextServer() {
    this.index = (this.index + 1) % this.servers.length;
    return this.servers[this.index];
  }
}

class AXFRQuery {
  constructor(options) {
    this.buf = Buffer.allocUnsafe(MAX_MESSAGE_SIZE);
    this.target = 0;
    this.size = 0;
    this.id = 0;
    this.msgs = [];
    this.ok = false;
    this.socket = null;
    this.resolve = null;
    this.reject = null;
    this.qs = new Question(options.zone, types.AXFR);
    this.maxTimeout = options.maxTimeout;
    this.maxMessages = options.maxMessages;
  }

  async exchange(port, host) {
    this.socket = new net.Socket();
    this.socket.setTimeout(this.maxTimeout);
    this.socket.connect(port, host, () => {
      const req = new Message();
      req.opcode = opcodes.QUERY;

      this.id = util.id();
      req.id = this.id;
      req.question.push(this.qs);

      const msg = req.encode();
      const len = Buffer.allocUnsafe(2);
      len.writeUInt16BE(msg.length, 0);

      this.socket.write(len);
      this.socket.write(msg);
      this.socket.end();
    });

    this.init();

    return new Promise((resolve, reject) => {
      this.resolve = resolve;
      this.reject = reject;
    });
  }

  init() {
    this.socket.on('data', (data) => {
      try {
        this.read(data);
      } catch (e) {
        this.socket.destroy();
        this.reject(e);
      }
    });

    this.socket.on('timeout', () => {
      this.socket.destroy();
      this.reject(new Error('Timed out'));
    });

    this.socket.on('error', (e) => {
      this.socket.destroy();
      this.reject(e);
    });

    this.socket.on('close', () => {
      this.socket.destroy();
      if (!this.ok)
        this.reject(new Error('Closed unexpectedly'));
    });
  }

  read(data) {
    let off = 0;
    if (this.target === 0) {
      assert(data.length > 1, 'Malformed packet received');
      this.target = data.readUInt16BE(0);
      off = 2;
    }

    data = data.slice(off, data.length);
    let writeLength = data.length;
    let remaining = null;

    // write length exceeds target
    if (this.size + writeLength > this.target) {
      writeLength = this.target - this.size;
      remaining = data.slice(writeLength, data.length);
    }

    data.copy(this.buf, this.size, 0, writeLength);
    this.size += writeLength;

    if (this.size === this.target) {
      const msg = Message.decode(this.buf.slice(0, this.target));
      assert(msg.id === this.id, 'Message id does not match');
      assert(msg.answer.length !== 0, 'Empty message');

      if (this.msgs.length === 0)
        assert(msg.answer[0].type === types.SOA, 'First record must be SOA');

      if(this.msgs.length + 1 > this.maxMessages)
        throw new Error('Transfer is too large ' +
          '(max messages: ' + this.maxMessages + ')');

      this.msgs.push(msg);
      const last = msg.answer[msg.answer.length - 1];
      if (last.type === types.SOA) {
        this.ok = true;
        this.socket.destroy();
        this.resolve(this.msgs);
        return;
      }

      this.target = 0;
      this.size = 0;
    }

    if (remaining != null)
      this.read(remaining);
  }
}

class AXFRValidator {
  constructor() {
    this.owners = new Map();
    this.maybeGlue = new Set();
    this.origin = '.';
  }

  verifyZone(messages, keyMap) {
    // prepare data for dnssec.verifyMessage
    for (const message of messages) {
      for (const rr of message.answer) {
        // potentially a glue record
        if (rr.type === types.NS) {
          this.maybeGlue.add(rr.data.ns);
        }

        if (rr.type === types.NSEC3)
          throw new Error('bogus: NSEC3 not supported');

        let owner = this.owners.get(rr.name);
        if (!owner) {
          owner = {delegation: false, rrs: []};
          this.owners.set(rr.name, owner);
        }

        if (rr.type === types.NS && rr.name !== this.origin)
          owner.delegation = true;

        owner.rrs.push(rr);
      }
    }

    const buf = new Message();
    const glue = new Set();
    for (const [name, owner] of this.owners) {
      buf.answer = owner.rrs;
      // skip validating NS record for delegations
      if (owner.delegation)
        buf.answer = util.filterSet(buf.answer, types.NS);

      // skip glue records
      if (this.maybeGlue.has(name)) {
        // glue must be in a delegated sub-tree
        const tld = util.fqdn(util.from(name, -1));
        const parent = this.owners.get(tld);
        if (parent && parent.delegation) {
          // glue must only have A and AAAA
          const set = util.filterSet(owner.rrs, types.A, types.AAAA);
          if (set.length === 0) {
            glue.add(name);
            continue;
          }
        }
      }

      // validate all rr sets for this owner
      if (!dnssec.verifyMessage(buf, keyMap))
        throw new Error('bogus: unable to validate zone data for ' + name);
    }

    // NSEC chain must be valid and complete
    const nsecChain = this.verifyNSEC();

    return {
      glue: glue,
      names: this.owners,
      nsecChain: nsecChain
    };
  }

  // Verify that the NSEC chain
  // and type bitmaps are complete
  verifyNSEC() {
    let name = this.origin;
    const seen = new Set();
    seen.add(this.origin);

    for (;;) {
      const owner = this.owners.get(name);
      if (!owner)
        throw new Error('bogus: invalid data');

      const rrs = util.extractSet(owner.rrs, name, types.NSEC);
      if (rrs.length !== 1)
        throw new Error('bogus: NSEC must exist for ' + name);

      const rr = rrs[0];
      this.verifyBitmap(name, owner, rr.data.getTypes());

      name = rr.data.nextDomain;
      // could be a loop it should only be seen
      // if it was the origin
      if (seen.has(name)) {
        if (name !== this.origin)
          throw new Error('bogus: bad NSEC chain');

        break;
      }
      seen.add(name);
    }

    return seen;
  }

  verifyBitmap(name, owner, bitmap) {
    let hasNS = false;
    for (const type of bitmap) {
      if (type === types.NS)
        hasNS = true;

      if (!util.hasType(owner.rrs, type))
        throw new Error('bogus: could not find type ' + type + ' for ' + name);
    }

    if (owner.delegation && !hasNS)
      throw new Error('bogus: claim to have a delegation ' +
        'yet no NS in NSEC bitmap for ' + name);
  }
}

class MessageWriter {
  constructor(req, write) {
    this.write = write;
    this.req = req;
    this.msg = new Message();
    this.msg.setReply(this.req);
    this.reset();
    this.written = 0;
  }

  reset() {
    this.msg.answer = [];
    // approximate size without compression
    this.size = this.msg.getSize(null);
  }

  async writeRR(rr) {
    this.written++;
    const size = rr.getSize(null);
    if (size + this.size > MAX_MESSAGE_SIZE)
      await this.flush();

    this.size += size;
    this.msg.answer.push(rr);
  }

  async writeAll(rrs) {
    for (const rr of rrs)
      await this.writeRR(rr);
  }

  async flush() {
    if (this.size === 0)
      return;

    const ok = await this.write(this.msg.compress());
    if (!ok)
      throw new Error('unable to write message');

    this.reset();
  }
}

function assert(cond, msg) {
  if (!cond)
    throw new Error(msg);
}

exports.AXFRClient = AXFRClient;
exports.AXFRValidator = AXFRValidator;
exports.MessageWriter = MessageWriter;
