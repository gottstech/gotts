# Introduction to Mimblewimble, Grin & Gotts

[Mimblewimble](https://github.com/gottstech/gotts/wiki/A-Brief-History-of-MimbleWimble-White-Paper) is a blockchain format and protocol that provides extremely good scalability, privacy and fungibility by relying on strong cryptographic primitives.

[Grin](https://github.com/mimblewimble/grin) is the first open source software project that implements a Mimblewimble blockchain, with completely community driven model.

The main technical characteristics of the Grin project are:

* Privacy by default. This enables complete fungibility.
* Scales mostly with the number of users and minimally with the number of transactions, resulting in a large space saving compared to other blockchains.
* Strong and proven cryptography. Mimblewimble only relies on Elliptic Curve Cryptography which has been tried and tested for decades.
* Design simplicity that makes it easy to audit and maintain over time.

For the detail, please refer to [Grin Introduction](https://github.com/mimblewimble/grin/blob/master/doc/intro.md).

**Gotts** is a new journey that based on Grin codebase, and will implement the following major differences and improvements:

* Decentralized stable-coins, non-collateralized, transaction as immediate conversion.
* Public value transaction, <ins>stealth</ins> address and transaction proof. 
* ~~Both interactive and~~ non-interactive transaction~~s are supported~~.
* 10x transaction throughput comparing to Grin.
* Super Lightweight.

## The Ideal of Peer-to-Peer Electronic Cash

Recall the 1st sentence of Bitcoin whitepaper:

> _"A purely **peer-to-peer** version of **electronic cash** would allow online payments to be sent directly from one party to another without going through a financial institution."_ -- ***Satoshi Nakamoto, 2008***

Bitcoin has got an incredible success as a store of value, but we could say it's far from a success for the original "p2p electronic cash" ideal.

> _"Bitcoin is 10 years old now, it’s become impossible to change meaningfully and those 10 years represent a century given how much has been researched and developed since.
When the Mimblewimble white paper was published, it seemed like a good base to attack the goal head on."_ -- ***Ignotus Peverell, 2019*** 

Definitely **Grin** is a vigorous attack to this ideal, with excellent improvements on privacy and scalablity. While **Gotts** will think differently and attack from other sides: currency stability, usability and capacity.

A useful currency should be a medium of exchange, a unit of account, and a store of value. But as a unit of account, cryptocurrencies are pretty bad, because of extreme price fluctuations. A cryptocurrency’s price volatility, in the long run, hinders the real-world adoption.

This is where stablecoins come in. We're not going to analyze the existing stablecoins here. Generally speaking, all of them are collateral based, either fiat-collateralized or crypto-collateralized, either requires trust in a centralized entity, or takes a big risk on the volatility of the underlying collateral crypto assets. So far, there's no non-collateralized stablecoins running. But we do believe it should have.

## Abstract

Gotts could be the 1st blockchain for non-collateralized stablecoins. With the price info integrated into block headers, which are provided by Gotts price feeders, a native transaction in Gotts can achieve the immediate conversion between the Gotts stablecoins assets. And the redemption is guaranteed by the chain, in a completely decentralized way.

Regarding the usability, ***Interactive Transaction*** is great in some use cases, where the receiver has a public server with a domain and a well https setup. But indeed, it's very difficult for common people when receiving. Although there're some workaround solutions to help on that, the most simple solution must be the ***address*** and the ***Non-Interactive Transaction***. Gotts support the latter.

Gotts remove the bulletproof, the heaviest part of the transaction data, which in Mimblewimble is used to hide the transaction amount but can prove it is in `[0, 2^64]`, to have the explicit amount. We get a fairly well paid off: capacity improvement. Gotts implement the ***10x*** transaction throughput comparing to Grin, even this is still far below the Visa average transaction rate, which was about [4,000 txs](https://usa.visa.com/dam/VCOM/download/corporate/media/visanet-technology/aboutvisafactsheet.pdf) at 2018, but we got it almost free. We believe this improved capacity will also help a lot on the real world adoption for Gotts payment, a further step to the ideal of Peer-to-Peer Electronic Cash.

## Table of Contents
- [Gotts Stablecoins](#gotts-stablecoins)
- [Public Value Transaction](#public-value-transaction) 
- [Gotts Interactive Transaction](#gotts-interactive-transaction)
- [Gotts Non-Interactive Transaction](#gotts-non-interactive-transaction)
- [Gotts Stealth Address](#gotts-stealth-address)
- [Cut-Through, Pruning and Super Lightweight](#mimblewimble-cut-through-and-lightweight-chain)

And more related contents in the WiKi pages: [https://github.com/gottstech/gotts/wiki](https://github.com/gottstech/gotts/wiki).

## Gotts Stablecoins

Stablecoins are price-stable cryptocurrencies, meaning the market price of a stablecoin is pegged to another stable asset, such as the US Dollar, Euro, Chinese Yuan, Japanese Yen, British Pound, Canadian Dollar, and so on.

### How to Ensure a Stable Price

In fact, Gotts price will be volatile, just like any other cryptocurrencies. Gotts coin is not a stable coin.

Instead, in Gotts system, the stable coins are those on-chain assets, such as GOUS, GOEU, GOCN, etc.

For any stablecoin assets on Gotts chain, at any time, any amount of them can be converted to proper amount of Gotts coins which have the equal face value of those stablecoins, ensured in a completely decentralized way.

Say, at a time, we have `M` Gotts coins and `N` GOUS (a symbol of US dollar pegged stablecoin) assets on chain, suppose the current Gotts price is `R` (US$/Gotts), and GOUS is the only stable coin asset in Gotts system.

Then, at this time, the total assets value on chain are:
```sh
Total Value (US$) = M * R + N

Where M is the total circulation of Gotts coins,
N is the total circulation of GOUS stable-coins in the system,
R is the current Gotts coin price in US$.
``` 

If `P` GOUS need to be converted to fiat US dollar, supposing we always use Gotts coin as the intermediate medium, we can imagine a single simple transaction on the chain:
```sh
Input = P GOUS
Output = Q Gotts

where Q = P / R, R is the current Gotts coin price in US$.
```
And at this moment, the total assets value on chain are still kept exact same when any converting transaction happen:
```sh
Total Value (US$) = (M + P/R)*R + (N-P) = M * R + N
```

So, this means, in any time, for any amount of stablecoin assets on Gotts chain, the chain 100% ensure its face value as the pegged asset such as USD, EUR, CNY, JPN, GBP, CAD and so on.

This procedure is completely decentralized. Anybody can execute a **conversion** by him/her self at any time, just as simple as a normal transaction on the chain.

As you see, the basic idea of Gotts stable coins is the on-chain **conversion** transaction, with the following main characteristics:

- Completely decentralized.
- Transaction as the immediate conversion / issuance.
- It's the chain who ensure these stable-coins asset redeemable, with equal value, at any time.
- Obviously not backed by fiat currencies.

It looks very like a crypto-collateralized stable-coins but actually it's NOT, here the crypto asset refers to the Gotts coin.

The biggest risk to the crypto-collateralized stablecoin model is the volatility of the underlying collateral. So, normally it requires over-collateralization, moreover, once the collateral lose too much value, the liquidation procedure is forced to be enabled because under-collateralized.

But this is not the case for Gotts stable coins. Gotts coin's volatility has no impact on these on-chain stable coins assets, and over-collateralization is also not needed here.

Regarding the stable-coins issuance, there is no special issuance procedure for any stable-coin in Gotts system. Anyone, in anytime, can "issue" some amount of stable-coin with the equal value Gotts coins, by a simple native conversion transaction.

### What's the Impact of Gotts Price Volatility

The price changing of the **Gotts** coin has no impact on stablecoins assets.

Say, the Gotts price change from ***R*** (US$/Gotts) to ***R'*** (US$/Gotts). And let's still use above conversion example:

```
Input = P GOUS
Output = Q' Gotts
where Q' = P / R'

Total (US$) = (M + P/R')*R' + (N-P) = (M*R'+P) + (N-P) = M*R' + N
```
As we can see, the `R'` only impact the amount of output Gotts (i.e. `Q'`). All the pegged asset's face value is still kept same as `N`, when Gotts price change and `P` GOUS converted to fiat US dollar (via Gotts coins).

With this design, even in extremely impossible situation, if Gotts price is falling dramatically and all the Gotts has been converted to GOUS, or if Gotts price is rising dramatically and all the GOUS has been converted to Gotts coin, there's no problem for the system continue working correctly.

For the stability, the ONLY risk is the event of the whole crypto crash, traders tend to exit to fiat currencies, not stablecoins and not Gotts coin. But that will be quite impossible once Gotts chain published, just like talking about shutdown of Bitcoin network. 

### What's the Impact on Gotts Price

Ostensibly, the redemption of these stable coins asset will cause the inflation or deflation of the Gotts coin.

In normal case, for any currency, the inflation or deflation of issuance will definitely impact the price, either gradually or significantly.

But for Gotts system, there're multiple on-chain assets. Gotts coin asset is just one of these assets, together with all those stable coins asset, such as GOUS, GOEU, GOCN, etc.

So, to evaluate the total supply, we have to consider all of them, not just Gotts coin. More conversions from Gotts coin to those stable coins, means more stabilized total supply value in the whole system.

The maximum circulating supply of Gotts coin is NOT the right indicator of Gotts system. Instead, the total assets circulating supply does.

### Gotts Deflation when Price Rising

When Gotts price is rising, the maximum circulating supply of Gotts will decrease accordingly, which will cause a little bit "deflation", in the narrow sense of the word.

Say, we have `M` Gotts coins and `N` GOUS on chain. The Gotts price rise from `R` to `R'`:
```
Total (Gotts) = M + N/R
when R' > R, Total' (Gotts) = M + N/R'

   Total' - Total = N*(1/R' - 1/R) = N*(R-R')/(R*R') < 0
=> Total' < Total
```
This "deflation" can push a little bit further price rising, i.e. a positive feedback.

But when Gotts price is rising, there's a nature stimulation for more conversion from GOUS to Gotts, which will weaken this price positive feedback, until a new balance.

And vice versa, there's the narrow sense "inflation" when Gotts price falling, but a nature stimulation for more conversion from Gotts to GOUS will weaken the positive feedback, until a new balance.

### Which Stablecoins it Support

In the first release of Gotts mainnet, the following stablecoins will be planned to be supported:

* GOUS  (pegged to fiat US dollar)
* GOEU  (pegged to fiat Euro)
* GOCN  (pegged to fiat Chinese Yuan)
* GOJP  (pegged to fiat Japanese Yen)
* GOUK  (pegged to fiat British Pound)
* GOCA  (pegged to fiat Canadian Dollar)

If any other pegging assets are requested and agreed by the community, we can add in the future releases.

### Conversion Between Gotts Stablecoins

If user want to convert directly from one stablecoin to another one, for example converting GOUS to GOJP, there's no need to convert between them and Gotts coin, the chain native transaction can support these cross conversion directly among all these stablecoins.

The price feed oracles need provide corresponding exchange prices, based on Foreign Exchange market info.

### Price Feed Oracles

Similar as [Maker DAI price feed oracles](https://developer.makerdao.com/feeds/), Gotts also use whitelist for price feeding.

Gotts price feed oracle has the following differences:

* Price feed oracle has part of block rewards, as the subsidy to cover the cost of running the price feed service.
* Each price feeder provide a stake for its honesty. If a price feed oracle has any intentional or unintentional bad behavior, such as not in service, fault price, and so on, the staked coins will be slashed, and a penalty on the rewards acquirement.   
* The staked coins will be locked for half an year, until next planed hardfork to change consensus for the new list of price feed oracles.

If a block reward is 60 Gotts, 10% of this reward will go to the price feed oracles, and 90% will go to the miner. And the penalty of the fault price feed (if have) will go to the miner as the additional reward.

For identification of these price feed oracles, each one has an open public key integrated as the consensus of Gotts chain. And each time when a price feed oracle publish a price, the corresponding signature must be attached.

Here is a draft example of a price feed message structure in Rust:
```Rust
struct PriceFeed {
   timestamp: u32,
   pair_price: [(u8,u32); MAX_PAIRS],
   price_feeder: u8,
   sig: Signature,
}
```
And for each block, we integrate `15 PriceFeed` into it, the cost is about 1.5 ~ 3.0 K bytes for that.

More price feed oracles means more safe for Gotts, but we need store these price feed data on chain, and storing all these price feed data is too expensive for the chain. So, in Gotts, we only store `15` price feed oracles data, i.e. we limit the size of vector `PriceFeed` to `15`.

Even we have this limitation, we still give the whole (`100` for example) price feed oracles list in our consensus file, with each of their public key. This consensus part looks like:
```Rust
   const price_feed_oracle_pubkeys = [
       "0x1234...",
       "0x4321...",
       ...
       "0xabcd...",
   ];
```
With this `15` out of `100` maximum available price feed oracles, we get good robustness for these important price feeds.

To avoid the miner's preference on some price feed oracles, we can use a random seed to get the positions in these `100` price feed oracles. For example, we use a part of the block header as the random seed and get a hash, and use this hash to decide `32` out of `100` price feed oracles. That `15` prices can only be chosen from these `32` random price feed oracles.

### Fault Evidence, Penalty, and Blacklist of Price Feed Oracles

In case a fault price seen on any price feed oracle, the miner will fine an amount from that oracle's staked coins, and record the related evidence into the chain so that any node can verify this fault price and validate this fine.

The fine amount is 10 times of the price feed reward for one block. For example if the price feed reward of a block is 6 Gotts, the fine amount will be 60 Gotts.

This fine becomes the additional reward for the miner of this block.

And before the price feeder pay the fine ticket, it can't get any new reward, and all its price feeds will be ignored.

And in case a fine ticket is hung for more than 48 hours, the price feed oracle will be added into the blacklist, and all the nodes in the network will ban the peer/s who send/forward the price feed of the blacklist oracles. The default banning period is one week.

### Conversion Transaction

To support the assets conversion, we need the asset type to be there in any Output. The structure could be like this:
```rust
struct Output {
	asset_type:[u8; 4],
	value: Option<u64>,
	/// The relative lock height, after which the output can be spent.
	relative_lock_height: u32,
	...
}
```
The `asset_type` is something such as 'GOUS', 'GOEU', Etc. The `value` for the raw conversion transaction output is a special type which allow `None`, because it will be calculated and filled by the miner only, according to current price info which will be integrated into next block header.

There're two consensus rule for Conversion Transaction:
1. A Conversion Transaction must be an interactive transaction. Normally we propose a "payment" to self, but to another also allowed.
2. The `relative_lock_height` must not be less than a consensus constant, for example `10` blocks, to avoid the practical re-org causing the cascading transactions spending this output invalidated because of the possible different price info in the re-org headers.

### Pegged to Arbitrary Asset

Since we can have GOUS on Gotts chain, it should be capable to simulate an arbitrary asset. For example, we should be able to have a **GBTC** which is pegged to BTC, a **GETH** to ETH, or even a **GOLD** to the real world gold.

Note: this is not a feature in first release.

### More

More researches: [https://github.com/gottstech/gotts/wiki/Gotts-Stable-Coins](https://github.com/gottstech/gotts/wiki/Gotts-Stable-Coins) 

## Public Value Transaction

Privacy is one of the main characteristics for Mimblewimble/Grin. And it definitely works with cost.

The 1st important cost is the big transaction size, comparing to Bitcoin. A typical transaction with single input and double outputs in Grin need about `1,558` bytes:

```
1 Input: 1+33 = 34 Bytes
2 Outputs: 2*(1+33+675) = 1,418 Bytes
1 Kernel: (1+8+33+64) = 106 Bytes
```
Note: Strictly speaking, the raw transaction has a 32-byte offset, so the final size of above transaction on transmitting is `1,590` bytes.
 
The heaviest part is the bulletproof which is about `85%` in a typical 1 input 2 outputs transaction.

The 2nd important invisible cost is about the real-world adoption. No matter how important the privacy is, the privacy coins are grouped as a special type, thought by common people for special use cases, for example the darknet, even actually they're not.

We design this public value transaction for Gotts, but it completely does not mean privacy protection is not important or Gotts does not care about privacy protection. Actually Gotts still provide very good privacy protection for the transaction address.

To emphasize it, Gotts want to attack the goal from another side: stability and usability. So, the 1st modification of Gotts on Mimblewimble is: **No privacy of amounts**, but still keep the privacy of addresses.

Removing the heaviest bulletproof will get roughly 6 times transaction capacity/throughput:
```
1,590 / (1,590 - 675*2) = 1,590/240 ~= 6.6 
``` 
Another well paid off item is the easiness to support the stablecoins, which will just be some public values on-chain assets then.

Moreover, it's convenient to get complete economic statistics regarding to the usage of these stablecoins assets, also for Gotts asset.

You can't get the total/daily transaction volume data on a privacy Mimblewimble/Grin, because of its perfect obscure amount.

***Note***: although we modify the Mimblewimble for the explicit amount, we will still have all other wonderful points of MimbleWimble: non-interactive coin-join, cut-through, etc.    

### Mimblewimble Modification for Public Value

In Mimblewimble paper, Tom described:

> the amounts are coded by the following equation:
> 
>     C = r*G + v*H
> 
> where C is a Pedersen commitment, G and H are fixed nothing-up-my-sleeve elliptic
> curve group generators, v is the amount, and r is a secret random blinding key.
> 
> Attached to this output is a rangeproof which proves that v is in [0, 2^64], so
> that user cannot exploit the blinding to produce overflow attacks, etc.

We will give a little modification on above equation:

- Replace `v` with `w`. And `w` is not the amount anymore, instead it's just a random number, but we still ensure the balance of `w` between inputs and outputs.
- Attached to this output is an explicit value `v`, instead of a rangeproof.

The reason to keep a random number `w` here is it can keep this Pedersen Commitment equation in Mimblewimble as it was.
```sh
C = r*G + w*H

where w is a random number, which can be a negative number,
and leave the amount value v as an explicit field in the output.
```

In Mimblewimble/Grin, this `w` is hidden into the bulletproof and must be positive value. Instead, in Gotts, because we removed the bulletproof, we have to hide this `w` into a secret which can only be decoded by the transaction parties, which will be explained more in next chapter.

For the all remaining parts of Mimblewimble, we keep same, except all the validations need check the explicit amount balance also.

## Gotts Interactive Transaction

The interactive transaction scheme has been removed, see the reason summarized [here](https://github.com/gottstech/gotts/wiki/Removing-Interactive-Transaction). The removed interactive transaction scheme can be found [here](https://github.com/gottstech/gotts/blob/v0.0.6/docs/intro.md#gotts-interactive-transaction).

## Gotts Non-Interactive Transaction

For most of personal users, when he/she is the receiver in a transaction, the ***Interactive Transaction*** is difficult to use for him/her, because the receiver need to be online and must be reachable for the sender's wallet, which sometimes will be very difficult or unstable or even impossible for personal user, especially for the NAT network environment.

There're some workaround solutions for example making transaction by file asynchronously. But that doesn't change the necessary ***interactive*** procedure, so the payer still need wait the payee sign the received file and send back to the payer, still difficult to use for personal users to receive coins.

But it's so popular and well-known in cryptocurrency world that the payment can be very easy thanks to "***Pay-to-Address***" / "***Pay-to-Public-Key-Hash***" technology.

So, in Gotts, for better user experience of personal user, and better adoption on common people, we enhance the Mimblewimble transaction so as to support such kind of "***Pay-to-Address***” concept, i.e. the ***Non-Interactive Transaction***.

### Non-Interactive Transaction Design

A dedicated document for non-interactive transaction has been split out as [nit.md](https://github.com/gottstech/gotts/blob/master/docs/nit.md).

## Gotts Stealth Address

### Stealth Address Design

(To Be Updated)

A dedicated research page in WiKi: [https://github.com/gottstech/gotts/wiki/Stealth-Address](https://github.com/gottstech/gotts/wiki/Stealth-Address) 

### Gotts Address Encoding

(To Be Updated)

~~As described above, to construct a non-interactive transaction, the sender must know a public key of the receiver. We name this public key as the **Gotts Address**.~~

~~Inspired by [BIP-0173](https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki) base32 address, we also use base32 coding for **Gotts Address**.~~

~~Comparing to [Base58](https://en.wikipedia.org/wiki/Base58) address coding, this base32 address has the following benefits:~~

| Address Scheme --> | Base32 | Base58 |
|:-------------|:-------------|:-----|
| QR Codes   | &#9745; Better | Needs a lot of spaces |
| write/read/type | &#9745; Better | Needs more care about the mixed case |
| Error-Detection | &#9745; Yes | No |
| Decoding Complexity | &#9745; Faster | Slower |

~~#### HRP (Human Readable Part)~~
We define two HRP prefixes for Gotts Address:
- `gs`:  for Gotts Mainnet address 
- `ts`:  for Gotts Floonet (testnet) address

~~#### Address Length~~

~~The public key need 33 bytes, and it's `62` characters in this base32 coding address, including the prefix `gs1` or `ts1`.~~

~~For example, here are some Gotts addresses:~~
- `ts1qgun5fxdnpn72kdz3myetqatgkxg7th5y0ymcnjcsf0n8nzzv8tc5q9uhkp`
- `ts1qgfaqdqyvm8ryd2k6zfp6cm359cs4gnudxhljmd0v38yut4u9r7rg93d4jp`
- `gs1qvgsq0kd7gvgqksg58fkqm9ms5cplcllev4fnwsvevuqs2jukrtrcguuvze`

### Price Feed Oracles Staking Transaction

[Price Feed Oracles](#Price-Feed-Oracles) need lock an amount of coins for half an year as the staking for their honesty.

There're two obvious requirement for this special staking transaction:

* The output must explicitly include the price feed oracle's ID, i.e. the public key hash which has been included in the chain consensus file.
* This output must be locked for half an year. 

### Price Feed Oracles Reward Transaction

It's quite different from the coinbase output which the miner create for him/her self. The price feed oracle reward output is created by the miner but locked by the price feeder's public key: an ***Non-Interactive Transaction*** output.

The `p2pkh` in the output is the rewarded price feeder's public key hash, which can be found in the consensus file. And the `lock_height` is current block height plus `1440`, the locking period is same as the coinbase output.

## Mimblewimble Cut-Through and Lightweight Chain
One of the most exciting parts in Mimblewimble is the cut-through feature. It can combine the transactions in the transaction pool, and even merge transactions across blocks, all the way down from the genesis block to the latest block. This merging will delete those spent outputs, and what remains are only the unspent outputs, and those transaction kernels.

Till 2019 Aug., Bitcoin has about total [450M](https://www.blockchain.com/charts/n-transactions-total) transactions, and need about [236GB](https://www.blockchain.com/en/charts/blocks-size) to save all these transactions in block chain database, because all the old transaction data must be kept there for security.

Comparing to Bitcoin, Mimblewimble scales mostly with the number of users and minimally with the number of transactions. Only that about [20M](https://bitinfocharts.com/top-100-richest-bitcoin-addresses.html) (at this time) Bitcoin non-empty addresses make sense here for estimating the total size of the necessary MimbleWimble chain data. Moreover, in MimbleWimble block chain, we can encourage combining UTXOs (the Input number has a negative weight when calculating the transaction fee), which will make the actual UTXO sets even much smaller than Bitcoin.
 
With above reasonable assumption, Mimblewimble/Gotts only need about **2GB** chain data for same level of users amount as Bitcoin today, with a rough assumption of an average 100 bytes for each unspent output in Gotts. A super lightweight chain!

### Super Fast Sync
Because of the much smaller size of the chain validation data, Mimblewimble block chain can have the super fast sync procedure. Only the following data are necessary to validate the whole chain:

- All block headers.
- All unspent outputs.
- All transaction kernels (Note: to be discussed in [kernel pruning](#transaction-kernel-pruning)).
- Recent full blocks, for example from two days to one week (i.e. a cut-through horizon size).


### 0-Confirmation Cascading Transaction
Both Grin and Gotts support 0-confirmation cascading transaction. A user can use one unspent output to create multiple (for example one thousand!) transactions for multiple receivers. For example at the payday, when the cashier need send salaries to a thousand employees, he/she can continuously operate sending, without any blocking to wait the block confirmations.

This is very useful for common people's adoption, who will get the same experience with any existing bank payment software.

```sh
tx1:    in = out1 + change1
tx2:    change1 = out2 + change2
tx3:    change2 = out3 + change3
...     ...
txn:    change(n-1) = out(n) + change(n)                 
```
In Mimblewimble, all above n transactions will look like one single transaction:
```
    in = out1 + out2 + out3 + ... + out(n) + change(n)
```
but with `n` transaction kernels instead of 1 transaction kernel for a simple transaction.

The Mimblewimble transaction pool accepts all of them as valid transactions, from `tx1` to `tx(n)`, with 0-confirmation of outputs `change1, change2, ... , change(n-1)`, at the exact same security level as the unspent output `in` (the 1st input of these transactions). 

### Transaction Kernel Pruning

At previous chapter, we say Mimblewimble is a super lightweight chain, because almost only unspent outputs need be kept as chain validation data, plus the block headers. And we also mentioned that all transaction kernel data are needed.

A typical transaction kernel in Gotts need about `1+4+33+64 = 102` bytes, refers to the pseudo-code here:
```Rust
struct TxKernel {
	features: KernelFeatures,
	fee: u32,
	excess: Commitment,
	excess_sig: Signature,
}
```

As we know, the average Bitcoin transaction size is about [~500 bytes](https://charts.bitcoin.com/btc/chart/transaction-size#5moc), and the basic Bitcoin transactions with 1 input and 2 outputs are typically [~225 bytes](https://www.blockchain.com/btc/tx/7e46a5ea9d9c19cd4d0c3d0a287419d7c1ae13049ac7ab8860b6ee0cec4ead17) of data.

Comparing to Bitcoin, if this `102` bytes transaction kernel data must be kept forever, that will be not very interesting for a concept of a "super lightweight chain", since the kernel size is `~45%` of the basic Bitcoin transaction size.

The meaning of a transaction kernel for the **block** validation:

- The signature of a transaction kernel must be ok, which proves the `excess` is a combined public key of the transaction parties (means somebody know the private keys), and implicitly proves the excess's amount component is zero. Otherwise, an illegal inflation happened.
- The `excess` sum of all the transaction kernels will be used to validate the big 0-sum of the block: all inputs plus reward, all output commitments, all kernels `excess`, plus the kernel offset in the header.

In Mimblewimble privacy transaction solution, it's so important for the chain validation to have the full transaction kernels signature verified, since which also implicitly proves the excess's amount component is zero, no any illegal inflation happened.

But in Gotts, we don't rely on that signature verification to detect illegal inflation, since all the amount are explicit here. So, for Gotts, comparing to the important meaning of a transaction kernel on the **block** validation, it is not much interesting for a quite old kernel on the **chain** validation, which becomes a pure dead weight.

:tada: We can prune the old transaction kernels in Gotts.