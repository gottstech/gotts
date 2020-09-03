# Design of Gotts Non-Interactive Transaction

## Old Design

The [old design of Gotts Non-Interactive Transaction](https://github.com/gottstech/gotts/blob/v0.0.6/docs/intro.md#gotts-non-interactive-transaction) has been completely implemented on node version [v0.0.6](https://github.com/gottstech/gotts/releases/tag/v0.0.6) and wallet version [v0.0.6](https://github.com/gottstech/gotts-wallet/releases/tag/v0.0.6) (but missing the necessary _ComSig_ signature for each output).

It use the Bitcoin style _Public-Key-Hash_ to lock the output. To spend a Non-Interactive Output, a Signature with the corresponding revealed Public Key must be provided as the unlocker. This is an intuitive and simple design, since the concept of P2PKH (Pay-To-Public-Key-Hash) is well known in crypto world.

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

Some examples here for the old design, taken from the working wallet version [v0.0.6](https://github.com/gottstech/gotts-wallet/releases/tag/v0.0.6).

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

The transaction size of above non-interactive transaction example (1 Input without the _Unlocker_ and 2 Outputs) is `12+(1+1+33)+(1+12+33+8)+(1+32+33+12+33+8)+(1+4+33+64)=322` bytes. (with the missing _ComSig_ signature, that will be 514 bytes.)


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

The transaction size of above non-interactive transaction example (1 Input with the _Unlocker_ and 2 Outputs) is 426 bytes. (with the missing _ComSig_ signature, that will be 618 bytes.)

Recently, I have been thinking whether it will be a better design to change back to pure Mimblewimble style "locker", i.e. the Pedersen Commitment, to get a more compact Non-Interactive Transaction solution.

## Mimblewimble-Style "Locker"

If considering the classic PKH (Public Key Hash) or Script Hash, i.e. the typical Bitcoin-style "locker", is an efficient way for locking, the Pedersen Commitment could be a better way, which can "lock" both the owner's Public Key and the output value, and it's capable to lock multiple Public Keys.

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

A prerequisite research has been done [here](https://github.com/gottstech/gotts/wiki/Non-Interactive-Transaction).

With this non-interactive transaction scheme, the _Output_ data structure in Gotts may be defined as:
```Rust
struct Output {
	features: OutputFeatures,
	commit: Commitment,
	value: u64,
	R: PublicKey,
	sig: ComSignature,
	spath: SecuredPath
}
```
The size of this _Output_ data structure is `1+33+8+33+96+12 = 183` bytes.

And the _Transaction_ data structure may be defined as:
```Rust
struct Transaction {
	excess: Commitment,
	inputs: Vec<InputEx>,
	outputs: Vec<Output>,
}

struct Input {
	features: OutputFeatures,
	commit: Commitment,
}

struct InputEx {
	inputs: Vec<Input>,
    pubs: Vec<PublicKey>,
	sig: Signature,
}
```

The size of this _InputEx_ data structure is `64+(34+33)*n+4` bytes. In case of single input, this size is 135 bytes.

### TxKernel

In Gotts, the `TxKernel` is same as the original Mimblewimble protocol. 

### Transaction Size Comparing

The final size of a typical transaction with 1 Input and 2 Outputs in Gotts will be about 644 bytes. This is less than the old non-interactive transaction scheme, even with the added _Stealth Address_ feature, especially the simple structure and the clear security model, the new non-interactive transaction scheme is much better.

| Size (Bytes) | Old Interactive Transaction | Old Non-Interactive Transaction | New Non-Interactive Transaction |
|:-------------|:-------------|:-------------|:-------------|
| 1 payment with 1 Input   | 436 | 618  | 644 |

Notes:

- Suppose the old non-interactive transaction include _InputUnlocker_, meaning the Input is a non-interactive transaction output.
- Suppose the old interactive transaction doesn't include any _InputUnlocker_, meaning the Input is not a non-interactive transaction output.

The old interactive transaction scheme has the optimal transaction size, but since the size is near to the new non-interactive transaction and the increased complexity to support two types of transactions, especially the bad usability of the interactive transaction for end user, therefore [decided to remove](https://github.com/gottstech/gotts/wiki/Removing-Interactive-Transaction#removing-interactive-transaction)).

The detail sizes of the Gotts transaction with 1 Input 2 Outputs:

| Name | Size (bytes) |
|:-------------|:-------------|
| excess | 33 |
|~~~|~~~|
| InputEx vector size | 4 |
| Input vector size | 4 |
| 1 Input | 34 |
| 1 p*R | 33 |
| InputEx signature | 64 |
| Output vector size | 4 |
| 2 Output | 183*2=366 |
| 1 TxKernel | 102 |
|~~~|~~~|
| Total |  644 |

The detail sizes of the Gotts output:

| Name | Size (bytes) |
|:-------------|:-------------|
| feature flag | 1 |
| commitment | 33 |
| value | 8 |
| R | 33 |
| output ComSig signature | 96 |
| secured path | 12 |
|~~~|~~~|
| Total | 183 |
 
PS. Data Structures:
```Rust
struct Transaction {
	inputs: Vec<InputEx>,
	outputs: Vec<Output>,
    kernels: Vec<TxKernel>
}

struct Input {
	features: OutputFeatures,
	commit: Commitment
}

struct InputEx {
	inputs: Vec<Input>,
    pubs: Vec<PublicKey>,
	sig: Signature
}

struct Output {
	features: OutputFeatures,
	commit: Commitment,
	value: u64,
	R: PublicKey,
	sig: ComSignature,
	spath: SecuredPath
}
```

 














   



















