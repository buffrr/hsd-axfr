/*!
 * axfr.js - AXFR plugin for hsd
 * Copyright (c) 2021 Buffrr (MIT License).
 */

'use strict';

const plugin = exports;

// this is probably a very hacky way
// to get those dependencies from hsd
const NameState = require('../../lib/covenants/namestate');
const {Resource} = require('../../lib/dns/resource');

const {
  wire,
  util
} = require('bns');

const {
  Message,
  types,
  codes
} = wire;

/**
 * Plugin
 */

class Plugin {
  /**
   * Create a plugin.
   * @constructor
   * @param {Node} node
   */

  constructor(node) {
    this.ns = node.ns;
    this.logger = node.logger.context('axfr');
    this.chain = node.chain;
    this.ipList = node.config.str('axfr-allow-ips', '127.0.0.1').split(/[ ]+/);
    // max number of rrs for each chunk sent
    this.chunkLength = node.config.int('axfr-chunk-length', 1500);

    // root server and full node are required
    if (!this.ns || this.chain.options.spv)
      return;

    this.ns.middle = async (tld, req, rinfo) => {
      const [qs] = req.question;
      const {name, type} = qs;
      if (name === '.' && type === types.AXFR)
        return await this.sendAXFR(req, rinfo);

      return null;
    };
  }

  // Send zone transfer
  // https://tools.ietf.org/html/rfc5936
  async sendAXFR(req, rinfo) {
    const {port, address, tcp} = rinfo;
    if (!tcp) {
      this.logger.debug('No zone transfer requests over udp.');
      // AXFR isn't designed for udp
      return this.refuse();
    }

    if (!this.ipList.includes(address)) {
      this.logger.debug('Address %s cannot send zone transfer request ' +
        'check allowed ip addresses.', address);

      return this.refuse();
    }

    this.logger.debug('Starting zone transfer.');
    let res = new Message();
    res.setReply(req);

    // first message has SOA
    res.answer.push(this.ns.toSOA());

    const tree = this.chain.db.tree;
    const iter = tree.iterator(true);
    let progress = 0;

    // this is based on the dumpzone rpc call
    // in hsd (not yet merged)
    while (await iter.next()) {
      const {value} = iter;
      const ns = NameState.decode(value);

      if (ns.data.length <= 0)
        continue;

      const fqdn = util.fqdn(ns.name.toString('ascii'));
      const resource = Resource.decode(ns.data);
      const zone = resource.toZone(fqdn);

      for (const rr of zone) {
        if (rr.type === types.RRSIG)
          continue;

        res.answer.push(rr);
        progress++;

        // write a new dns message every x rrs
        // chunk shouldn't be too big (up to 65535 octets)
        if (res.answer.length > this.chunkLength) {
          this.logger.debug('Transfer progress ', progress);
          await this.ns.server.write(res.compress(), port, address);
          res = new Message();
          res.setReply(req);
        }
      }
    }

    // send any remaining rrs
    // add SOA since its the last message
    res.answer.push(this.ns.toSOA());

    this.logger.debug('Transfer progress ', progress);
    this.logger.debug('Zone transfer complete');

    return res;
  }

  refuse() {
    const res = new Message();
    res.code = codes.REFUSED;
    return res;
  }

  open() {
    this.logger.info('AXFR plugin is active.');
    this.logger.info('Allowed IP addresses:', this.ipList.join(', '));
  }

  close() {
  }
}

/**
 * Plugin name.
 * @const {String}
 */

plugin.id = 'axfr';

/**
 * Plugin initialization.
 * @param {Node} node
 * @returns {WalletDB}
 */

plugin.init = function init(node) {
  return new Plugin(node);
};
