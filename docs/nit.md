# New Design of Gotts Non-Interactive Transaction

The [original design of Gotts Non-Interactive Transaction](https://github.com/gottstech/gotts/blob/v0.0.6/docs/intro.md#gotts-non-interactive-transaction) has been completely implemented on node version [v0.0.6](https://github.com/gottstech/gotts/releases/tag/v0.0.6) and wallet version [v0.0.6](https://github.com/gottstech/gotts-wallet/releases/tag/v0.0.6).

It use the Bitcoin style Public Key Hash to lock the output. To spend a Non-Interactive Output, a Signature with the corresponding revealed Public Key must be provided as the unlocker. This is an intuitive and simple design, since the concept of P2PKH (Pay-To-Public-Key-Hash) is well known in crypto world.

But the cost of combining the Bitcoin-style P2PKH with Mimblewimble is not trivial. The NIT (Non-Interactive Transaction) output need a `OutputLocker` structure which is `65-bytes` bigger than original Mimblewimble native output. And when spending this NIT output, an additional `InputUnlocker` is needed for unlocking it, which is `104-bytes` length. Considering the typical Gotts interactive transaction size is just `244` bytes, neither `OutputLocker` nor `InputUnlocker` is trivial for Gotts transaction. 

Let's recall these two data structure here:
```Rust
struct OutputLocker {
	/// The Hash of 'Pay-to-Public-Key-Hash'.
	p2pkh: Hash,
	/// The 'R' for ephemeral key: `q = Hash(secured_w || p*R)`.
	R: PublicKey,
	/// A secured path message which hide the key derivation path and the random w of commitment.
	spath: SecuredPath,
}

struct InputUnlocker {
	/// Nonce for the signing message.
	nonce: u64,
	/// The signature for the output which has a locked public key / address.
	sig: Signature,
	/// The public key.
	pub_key: PublicKey,
}
```

To implement this NIT design, make all works fluently and kill all those bugs, I had spent two months. So, as a summary of the privious NIT design, let's present an example here taken from the working wallet version [v0.0.6](https://github.com/gottstech/gotts-wallet/releases/tag/v0.0.6).

<details>
 <summary>An Example of OutputLocker</summary>
 
```Json
            {
              "p2pkh": "4c4527db7dc4ac60146dd43c8755f9162d9020394b7f138248716dc8ea5bb167",
              "R": "03e54c4fecb14e86b08d837e68fc257c8c7e21484387b7779111e74fb08fdb5a7c",
              "spath": "cd2ce94830ab80707d85f452"
            }
```
</details>

<details>
 <summary>An Example of InputUnlocker</summary>
 
```Json
          {
            "nonce": 16182884338189852768,
            "sig": "fa86727f851bb0ad68ed7b5b60f5350e9d5ff584dc378587a8a68862b3682cd0f46e4e4eb4375d77bbdbb4c818c10f8bb6cd70b183ff1faae9202dd44ecd649e",
            "pub_key": "02b25ba03e337726d106adcbd5ddb26615f40dc2474d212562c11df03a6eb343a7"
          }
```
</details>

<details>
 <summary>A Complete Example of a Non-Interactive Transaction (1 Input without the _Unlocker_ and 2 Outputs)</summary>
 
```Json
{
  "body": {
    "inputs": [
      {
        "SingleInput": {
          "features": "Plain",
          "commit": "08f74968697788c7fc3c2c0946f96b9fc727fdc2fc6a8c8e7c13d2d070f9be679b"
        }
      }
    ],
    "outputs": [
      {
        "features": {
          "Plain": {
            "spath": "09912c2a6f86f3743f32b08b"
          }
        },
        "commit": "0970610d308ef79c3cdb9d1389b55e84a24ed309bb3f341208cb081fa8dbc93388",
        "value": 592540000000
      },
      {
        "features": {
          "SigLocked": {
            "locker": {
              "p2pkh": "5245844436d6006bdd2832d6d14d321dd23c8702f5daae50166a755fcb9630f3",
              "R": "03693534e9d96785ebfebf81decba1408e38d6c0570b3a4f5d0cf8689263f732db",
              "spath": "733b8d1342e4b997eb5287e7"
            }
          }
        },
        "commit": "09e28b3c50ba19c7c1f43cebd934dd1a677d96eb110ab23ef56f5faf8f7205aee7",
        "value": 199310000000
      }
    ],
    "kernels": [
      {
        "features": {
          "Plain": {
            "fee": 8000000
          }
        },
        "excess": "09356dd90cce15bcea03642c16ac94c4f35aff49e6bb1613adb420506ceb5d9d93",
        "excess_sig": "c940db5286d6ec46523565905194174f62e4b01bfca9e25d687f828cc4aa8ffd4138c459c7eb90f649758c37aff753d39e01446c272bc29e12e87a3c6694eb9f"
      }
    ]
  }
}
```
</details>

The transaction size of above non-interactive transaction example (1 Input without the _Unlocker_ and 2 Outputs) is 309 bytes.


<details>
 <summary>A Complete Example of a Non-Interactive Transaction (1 Input with the _Unlocker_ and 2 Outputs)</summary>
 
```Json
{
  "body": {
    "inputs": [
      {
        "InputsWithUnlocker": {
          "inputs": [
            {
              "features": "SigLocked",
              "commit": "08e79e44557a62f53d37c72194f8e381030da80294c18820326280ee398eec39c3"
            }
          ],
          "unlocker": {
            "nonce": 2135360374869037106,
            "sig": "48d4ec103c73afd05311ea791698ff447b9b0bf1872b656d231faad05274b4d4c6525ac41255ad1ec164c6f79860a71dcd418daf05f0c1c848a6067c5a1d96c5",
            "pub_key": "02ad6b84c9cf5a71783be1095f6946cfb17541e548080496488d86a487f359102f"
          }
        }
      }
    ],
    "outputs": [
      {
        "features": {
          "Plain": {
            "spath": "cb8baac824fd75cca046051a"
          }
        },
        "commit": "0871577dc1d3e9467a38eac68427444a7195f5336e4c1c25d614069bf052dfddbe",
        "value": 899992000000
      },
      {
        "features": {
          "SigLocked": {
            "locker": {
              "p2pkh": "b33530e87b76a641806fe6a448efdbaf61db62e8c350fe57dddd58929f7ade28",
              "R": "035e589c25fc6b0dfe4951d108addc777c0fe4cf59ea0b0d85430d0f5df1c5f36f",
              "spath": "5bff98d7a2fc769575b2ec65"
            }
          }
        },
        "commit": "08486f23af753e46c53c1557507848cb774909c0569f30514f6e1e8082a03980e4",
        "value": 100000000000
      }
    ],
    "kernels": [
      {
        "features": {
          "Plain": {
            "fee": 8000000
          }
        },
        "excess": "099f364954fc555e6cae867969c0129eb3fabceebdd32684d5e0d6acf8510d6edd",
        "excess_sig": "aa48e889a50f4a186fc9f35f31337948b2e3c636d293f81635c387d507b760026e4087f41b21978f1c462a5b322962ca5684283b3041177302c0be4056900f06"
      }
    ]
  }
}
```
</details>

The transaction size of above non-interactive transaction example (1 Input with the _Unlocker_ and 2 Outputs) is 412 bytes.

Recently, I have been thinking whether it will be a better design to change back to Mimblewimble style "locker", i.e. the Pedersen Commitment, to get a more compact Non-Interactive Transaction solution.

## Mimblewimble-Style "Locker"

If considering the classic PKH (Pulic Key Hash) or Script Hash, i.e. the typical Bitcoin-style "locker", is an efficient way for locking, the Pedersen Commitment could be a better way, which can "lock" both the owner's Public Key and the output value, and it's capable to lock multiple Public Keys.

## The Prerequisite Researches

### ComSig Signature

There's a [ComSig signature scheme](https://github.com/gottstech/gotts/wiki/ComSig-Signature), which is a simple Schnorr signature with Pedersen commitment as key. 

The procedure of a ComSig, for a Pedersen commitment `C=x*G+w*H` ,is:

1. Select two random numbers `k1` and `k2`, calculate a Pedersen commitment `R=k1*G+k2*H`.
2. Calculate `e = Hash(R || C || m)`, where `m` is the signing message.
3. Calculate `k1 + e*x` as `u`, calculate `k2 + e*w` as `v`.
5. Done. The signature is `(R,u,v)`, for Pedersen Commitment `x*G + w*H` as signature public key.

Then anyone can verify this signature with the open Pedersen Commitment `C = x*G + w*H`, if:
```
u*G + v*H = R + e*C
```

### Stealth Address

In a blockchain system, address is an essential primitive which is used in transaction. The Stealth Address scheme is designed to protect the recipient privacy.

A prerequisite research on the stealth address has been done [here](https://github.com/gottstech/gotts/wiki/Stealth-Address) and the Gotts Stealth Address is designed as _(A<sub>i</sub>,B<sub>i</sub>,i)_, where _A<sub>i</sub>_ is the recipient _public spend key_ and _A<sub>i</sub>_ is the recipient _public view key_, _i_ is the child number which is within _[0,2<sup>31</sup>-1]_.

## New Design of Mimblewimble Non-Interactive Transaction

### Warm-up and Review: Mimblewimble/Grin Interactive Transaction Design

Looking back the Mimblewimble/Grin Interactive Transaction design, with 1 input and 2 outputs as example:
```
(ri*G + vi*H) + (excess'+ offset*G) = (rc*G + vc*H) + (rr*G + vr*H) + (0+fee*H)
```
Where

- `(ri*G + vi*H)` is the spending coin, i.e. the input, which is selected by the sender.
- `(rc*G + vc*H)` is the change coin, which is created by the sender.
- `(rr*G + vr*H)` is the sending coin which is created by the receiver.
- `ri` and `rc` are sender's private keys, `rr` is receiver's private key.
- `vi` is the input/spending coin amount, `vr` is the sending coin amount for the receiver, `vc` is the change amount.
- `fee` is the transaction fee for miner who validate and package this transaction.
- `offset` is the so-called "kernel offset", which is a random value selected by the sender. `offset` is transmitted as part of the transaction data, but only packaged into the block header as the "total offset", which accumulate all transaction `offset` value since the Genesis block. i.e. `offset` is not available on the chain data.
- `excess'` is the so-called "public excess", which is the public key for transaction kernel signature.

And we have the following relationships:

- `vi = vc + vr + fee`, which is used to calculate the change coin amount `vc`. 
- `excess' = (rc-ri-offset)*G + rr*G`, which is used to calculate the "public excess".

The Mimblewimble/Grin signature theme is the standard usage of Schonorr 2-of-2 aggregated signature: 
1. The sender notify the receiver his/her public key `P1 = (rc-ri-offset)*G` and a nonce `R1 = k1*G`.
2. The receiver take his/her public key `P2 = rr*G` and a nonce `R2 = k2*G`, calculate `P = P1+P2` and `R = R1+R2`.
3. The receiver send back to the sender: `P2`, `R2`, and the partial signature `s1 = k2+e*rr`, where `e = Hash(R || P || m)`.
4. The sender calculate his/her own partial signature `s2 = k1+e*(rc-ri-offset)`, then aggregate both partial signatures by `s = s1+s2`, to get the final aggregated signature: `(R, s)` and the final public key (i.e. the public excess): `P = P1+P2`.

Then, we have a "Transaction Kernel" as part of this transaction data, which include the transaction fee info and the signature data. Here is the pseudo-code of a transaction kernel data structure:
```Rust
struct TxKernel {
	fee: u64,
	excess': Commitment,
	excess_sig: Signature,
}
```

### Non-Interactive Transaction Design for Mimblewimble

Comparing to above Mimblewimble/Grin Interactive Transaction theme, now let's come to the new designed Mimblewimble Non-Interactive Transaction theme.

Still with the example which has 1 input and 2 outputs:

_(x<sub>i</sub>*G + w<sub>i</sub>*H) + Excess = (x<sub>c</sub>*G + w<sub>c</sub>*H) + (A<sub>i</sub>+B<sub>i</sub> + R'.x*H)_

Where

- _(x<sub>i</sub>*G + w<sub>i</sub>*H)_ is the spending coin, i.e. the input, which is selected by the sender.
- _(x<sub>c</sub>*G + w<sub>c</sub>*H)_ is the change coin, which is created by the sender.
- _x<sub>i</sub>_ and _x<sub>c</sub>_ are sender's private keys.
- _(A<sub>i</sub>+B<sub>i</sub> + R'.x*H)_ is the sending coin which is **also** created by the **sender**, where _A<sub>i</sub>_ and _B<sub>i</sub>_ are the elements of a receiver's wallet address, and _R'=r*B<sub>i</sub>_ where _r_ is a random secret selected by the sender, _R'.x_ is the point _R'_ x-coordinator.
- _Excess_ is the transaction public excess.

And we have the following relationships:

- _v<sub>i</sub> = v<sub>c</sub> + v<sub>r</sub> + fee_, which is used to calculate the change coin amount _v<sub>c</sub>_. 
- _Excess = (x<sub>c</sub>-x<sub>i</sub>)*G + (A<sub>i</sub>+B<sub>i</sub> + w<sub>e</sub>*H_, where _ w<sub>e</sub> = (w<sub>c</sub> - w<sub>i</sub> + R'.x) mod p_.

The _Excess_ is transmitted as part of the transaction data, but only packaged into the block header as the _Total Excess_, which accumulates all transactions _Excess_ value since the Genesis block. i.e. _Excess_ is not available on the block and chain data.

For the transaction signature public key, we define a _I_ for non-interactive transaction as the total inputs:

_I = SUM(inputs)_

Where, _I = x<sub>i</sub>*G + w<sub>i</sub>*H_ for above example with single input.

Using the _ComSig_ signature scheme, which only need to be executed on the sender side, a 96-bytes signature will be attached into the transaction, and as the additional data, both the _R_ and the _i_ (or an encoded _i'_) will be packed into the transaction.

With this non-interactive transaction scheme, the _Output_ data structure may be defined as:
```Rust
struct Output {
	features: OutputFeatures,
	commit: Commitment,
	v: u64,
	R: PublicKey,
    i: u32,
}
```
The size of this _Output_ data structure is `1+33+8+33+4 = 79` bytes.

And the _Transaction Kernel_ data structure may be defined as:
```Rust
struct TxKernel {
	features: KernelFeatures,
	accumulate_inputs: Commitment,
	excess_sig: Signature,
}
```
The size of this _Transaction Kernel_ data structure for a plain feature is `1+4+33+96 = 134` bytes.

The _Transaction_ data structure may be defined as:
```Rust
struct Transaction {
    excess: Commitment,
	inputs: Vec<Input>,
	outputs: Vec<Output>,
	kernels: Vec<TxKernel>,
}
```
With all these data structures, the size of a typical transaction with 1 Input and 2 Outputs is `33+(1+33)+79*2+134 = 359` bytes, which saves `67` bytes (or `15%`) data comparing to `426` bytes in the old non-interactive transaction scheme, even with the added _Stealth Address_ feature.

In case one transaction contains multiple payments (i.e. multiple outputs), this non-interactive transaction design is even more optimal than the interactive transaction even only on the size point of view. For example, for a transaction with 1 Input and 3 Outputs, the size is `33+(1+33)+79*3+134 = 438` bytes, whereas two old interactive transactions need `(1+33)*2+(1+33+8+12)*4+102*2 = 488` bytes, which contains 2 Inputs, 4 Outputs and 2 transaction kernels.

### Transaction Size Comparing

| Size (Bytes) | Old Interactive Transaction | Old Non-Interactive Transaction | New Non-Interactive Transaction |
|:-------------|:-------------|:-------------|:-------------|
| 1 payment with 1 Input   | 244 | 309  | 359 |
| 2 payments with 1 Input   | 244*2=488  | 309*2=618  | 359+79=438 |
| 3 payments with 1 Input   | 244*3=732  | 309*3=927  | 359+79*2=517 |

Notes:

- Suppose the old non-interactive transaction doesn't include any _InputUnlocker_, meaning the Input is not a non-interactive transaction output.
- Suppose the old interactive transaction doesn't include any _InputUnlocker_, meaning the Input is not a non-interactive transaction output.
- The new non-interactive transaction has the additional _Stealth Address_ feature.






   



















