[![Build Status](https://img.shields.io/travis/gottstech/gotts/master.svg)](https://travis-ci.org/gottstech/gotts)
[![Coverage Status](https://img.shields.io/codecov/c/github/gottstech/gotts/master.svg)](https://codecov.io/gh/gottstech/gotts)
[![Chat](https://img.shields.io/gitter/room/gotts_community/Lobby.svg)](https://gitter.im/gotts_community/lobby)
[![Documentation Wiki](https://img.shields.io/badge/doc-wiki-blue.svg)](https://github.com/gottstech/docs/wiki)
[![License](https://img.shields.io/github/license/gottstech/gotts.svg)](https://github.com/gottstech/gotts/blob/master/LICENSE)

# Gotts

Gotts is an in-progress implementation of the MimbleWimble protocol but with explicit amount transaction, and could be the 1st blockchain for non-collateralized stablecoins, based of [Grin `v2.0.0` Codebase](https://github.com/mimblewimble/grin/tree/v2.0.0).

Many characteristics are still undefined but the following constitutes a first set of choices:

  * Decentralized non-collateralized stable-coins, with perfect stability, as Gotts on-chain assets.
  * Transaction as immediate conversion between different stable-coins assets.
  * Follow MimbleWimble protocol, but with explicit amount transaction.
  * Support both interactive and non-interactive transaction.
  * Address and transaction proof.
  * 10x transaction throughput comparing to Grin.
  * Proof of Work.
  * Fixed block reward over time with a decreasing dilution.

To learn more, read the [Introduction to MimbleWimble, Grin & Gotts](docs/intro.md).

## Status

Gotts is still under development. Much is left to be done and [contributions](CONTRIBUTING.md) are welcome (see below), the [TODO](docs/TODO.md) may help. Check the [website](https://gotts.tech/) for the latest status.

## Contributing

To get involved, read our [contributing docs](CONTRIBUTING.md).

Find us:

* Chat: [Gitter](https://gitter.im/gotts_community/lobby).
* Mailing list: join the [~gotts.tech](https://launchpad.net/~gotts.tech) team and subscribe on Launchpad.
* Twitter for Gotts: [@gottstech](https://twitter.com/GottsTech)
* Telegram for Gotts: [t.me/gottstech](https://t.me/gottstech)

## Getting Started

To learn more about the technology, read our [introduction](docs/intro.md).

To build and try out Gotts, see the [build docs](docs/build.md).

## Philosophy

Gotts likes itself small and easy on the eyes. It wants to be inclusive and welcoming for all walks of life, without judgement. Gotts is terribly ambitious, but not at the detriment of others, rather to further us all. It may have strong opinions to stay in line with its objectives, which doesn't mean disrespect of others' ideas.

We believe in pull requests, data and scientific research. We do not believe in unfounded beliefs.

## Credits

Tom Elvis Jedusor for the first formulation of MimbleWimble.

Andrew Poelstra for his related work and improvements.

John Tromp for the Cuckoo Cycle proof of work.

J.K. Rowling for making it despite extraordinary adversity.

[Grin Developers](https://github.com/mimblewimble/grin/graphs/contributors) for the first wonderful implementation of MimbleWimble. The related code taken with thanks and respect, with license details in all derived source files.

[Bips Contributors](https://github.com/bitcoin/bips/graphs/contributors) for some taken proposals in Grin and/or Gotts, such as [bip-schnorr](https://github.com/sipa/bips/blob/bip-schnorr/bip-schnorr.mediawiki), [bip-32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki), [bip-39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki), [bip-152](https://github.com/bitcoin/bips/blob/master/bip-0152.mediawiki), [bip-173](https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki), and so on.

And all other contributors not explicitly mentioned above.

## License

Apache License v2.0.
