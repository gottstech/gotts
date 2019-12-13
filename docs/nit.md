# New Design of Gotts Non-Interactive Transaction

The [original design of Gotts Non-Interactive Transaction](https://github.com/gottstech/gotts/blob/v0.0.6/docs/intro.md#gotts-non-interactive-transaction) has been completely implemented on node version [v0.0.6](https://github.com/gottstech/gotts/releases/tag/v0.0.6) and wallet version [v0.0.6](https://github.com/gottstech/gotts-wallet/releases/tag/v0.0.6).

It use the Bitcoin style Public Key Hash to lock the output. To spend a Non-Interactive Output, a Signature with the corresponding revealed Public Key must be provided as the unlocker. This is an intuitive and simple design, since the concept of P2PKH (Pay-To-Public-Key-Hash) is well known in crypto world.

But the cost of combining the Bitcoin-style P2PKH with MimbleWimble is not trivial. The NIT (Non-Interactive Transaction) output need a `OutputLocker` structure which is `65-bytes` bigger than original MimbleWimble native output. And when spending this NIT output, an additional `InputUnlocker` is needed for unlocking it, which is `104-bytes` length. Considering the typical Gotts interactive transaction size is just `244` bytes, neither `OutputLocker` nor `InputUnlocker` is trivial for Gotts transaction. 

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

To implement this NIT design, make all works fluently and kill all those bugs, I have spent two months. So, it's my honor to present an example here taken from the working wallet version [v0.0.6](https://github.com/gottstech/gotts-wallet/releases/tag/v0.0.6).

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
 <summary>A Complete Example of a Non-Interactive Transaction (1 Input and 2 Outputs)</summary>
 
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

Recently, I'm thinking whether it will be a better design to change back to MimbleWimble style "locker", i.e. the Pedersen Commitment, to get a more compact Non-Interactive Transaction solution.

## MimbleWimble-Style "Locker"

If considering the classic PKH (Pulic Key Hash) or Script Hash, i.e. the typical Bitcoin-style "locker", is an efficient way for locking, the Pedersen Commitment is no-lose, which can "lock" both the owner's Public Key and the output value, and it's capable to lock multiple Public Keys.

Recall a simple form of Pedersen Commitment: `C = r*G + v*H`, the `r*G` is the Public Key component. One can spend this output `C` if he/she can prove the ownership by a Signature with the corresponding private key `r`. So, this `r*G` is acting as a locker for this output.

Now, let's construct a new input / output relationship for non-interactive transaction, with the help of above "locker" concept:
```
(ri*G + wi*H) + (r'*G + P) = (rc*G + wc*H) + (P + wr*H)
```
where

- `P` is the receiver's Public Key.
- we have `ri + r' = rc` and `wi = wc + wr`.

We can call this `r'*G + P` as `Offset`. Then, above form can be rewritten as:
```
Input + Offset = Change + Payment
```
Where

- `Input` is `ri*G + wi*H`, `Change` is `rc*G + wc*H`, `Payment` is `P + wr*H`.
- `Offset` is `(rc-ri)*G + P`. `P` is the receiver's Public Key.

With this design, the MimbleWimble sum balance character is well maintained. We can manage this `Offset` as an additional element in the Transaction data structure, and manage a `TotalOffset` in the block header to accumulate all transaction `Offset` since Genesis block.

To prove the ownership of these input coins, let's give another definition of `Excess`:
```
Excess = SUM( Input )
```
then, we just require a signature with this `Excess` as key.

But the problem is How to sign with `Excess` which has `H` component? since nobody know the private key of `H`, which is the conner stone of MimbleWimble privacy and it's generated by NUMS (Nothing Under My Sleeve) rule, refer to the detail info [here](https://github.com/garyyu/rust-secp256k1-zkp/wiki/Pedersen-Commitment#h).

Let's discuss the signature solution in next chapter.

## Signature with Commitment as Key

To sign with Pedersen Commitment `C = p*G + w*H` as the key, the basic idea is to use two signature instead of one.

Recall the Schnorr Signature theme for `p*G` as the key:

1. Select a random EC point `R1=k1*G`.
2. Calculate `e1 = Hash(R1 || P || m)`, where `P=p*G` is signer's public key, `m` is the signing message.
3. Calculate `k1 + e1*p` as `s1`, where `p` is signer's private key.
4. Done. The signature is `(R1,s1)`.

Remember `H` is an alternate secp256k1 generator, so we can have an exact same Schnorr Signature theme for `w*H` as the key:

1. Select a random EC point `R2=k2*H`.
2. Calculate `e2 = Hash(R2 || W || m)`, where `W=w*H`, `m` is the signing message.
3. Calculate `k2 + e2*w` as `s2`, where `w` is the one in Pedersen Commitment `p*G + w*H`.
4. Done. The signature is `(R2,s2)`.

One of the wonderful characters of Schnorr Signature is the aggregation. Now let's give the aggregation signature procedure:

1. Select two random EC points `R1=k1*G` and `R2=k2*H`, get `R=R1+R2`.
2. Calculate `C=P+W`, where `P` is signer's public key; `W=w*H` is the 2nd component in Pedersen Commitment `p*G + w*H`. We can see the `C` here is just the exact Pedersen Commitment itself.
3. Calculate `e = Hash(R || C || m)`, where `m` is the signing message.
4. Calculate `k1 + e*p` as `s1`, calculate `k2 + e*w` as `s2`.
5. Done. The signature is `(R,s1,s2)`, for Pedersen Commitment `p*G + w*H` as key.

Then anyone can verify this signature with the open Pedersen Commitment `C = p*G + w*H`:
```
S = s1*G + s2*H = R + Hash(R || C || m)*C
```

Let's prove it:
```
   S 
 = s1*G                           +   s2*H
 = k1*G + e*p*G                   +   k2*H + e*w*H
 = k1*G + Hash(R || C || m)*p*G   +   k2*H + Hash(R || C || m)*w*H
 = R1   + Hash(R || C || m)*(p*G) +   R2   + Hash(R || C || m)*(w*H)
 = (R1+R2) + Hash(R || C || m)*(p*G+w*H)
 = R + Hash(R || C || m)*C
```
Actually, because `H` is orthogonal to `G`, we have:
```
     (k1+e*p)*G + (k2+e*w)*H = s1*G + s2*H 
 ==> k1+e*p = s1,
     k2*e*w = s2
```
This means, by validating the signature via `S = R + Hash(R || C || m)*C`, we equivalently validated two signatures: both `(R1, s1)` and `(R2, s2)`.  That's wonderful, since we will have almost same speed on the signature verification as one single Schnorr signature.

### Signature for Multiple Inputs

In case a transaction is spending multiple input coins, we need the signature scheme to be able to prove the ownership of all those inputs. Let's take a look whether this signature scheme still works for this case.

For example, there're 2 inputs:
```
C1 = p1*G + w1*H
C2 = p2*G + w2*H
```

In case both inputs come from same wallet, actually we can simply combine these 2 inputs into one:
```
C = C1+C2 = (p1+p2)*G + (w1+w2)*H = p*G + w*H
```
then, we still can take them as same form as the case of one input. So, it definitely works in this case. The same combination method works for multiple inputs case.

But please note, for the special case which has different source of inputs, i.e. in case we can't get the combination of `p1+p2` (because nobody want to reveal the private key), the signature scheme of `(R,s1,s2)` doesn't work, because for example `(R,s11+s21,s12+s22)` is not equivalent to 4 independent signatures: `(R,s11)`, `(R,s21)`, `(R,s21)`, `(R,s21)`.

## New Design of MimbleWimble Non-Interactive Transaction

Thanks above MimbleWimble-Style locker and the signature theme with commitment as key, now we can have a more compact Non-Interactive Transaction solution.

### Warm-up and Review: MimbleWimble/Grin Interactive Transaction Design

Looking back the MimbleWimble/Grin Interactive Transaction design, with 1 input and 2 outputs as example:
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

The MimbleWimble/Grin signature theme is the standard usage of Schonorr 2-of-2 aggregated signature: 
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

### Non-Interactive Transaction Design for MimbleWimble

Comparing to above MimbleWimble/Grin Interactive Transaction theme, now let's come to the new designed MimbleWimble Non-Interactive Transaction theme.

(Even MimbleWimble/Gotts is the modified MimbleWimble to support the public value instead of the hidden value in MimbleWimble/Grin, I describe the privacy transaction solution here, which is a common technology both for Grin or Grin alike privacy chain, and for Gotts chain.)

Still with the example which has 1 input and 2 outputs:
```
(ri*G + vi*H) + offset' = (rc*G + vc*H) + (rr*G + vr*H) + (0+fee*H)
```
Where

- `(ri*G + vi*H)` is the spending coin, i.e. the input, which is selected by the sender.
- `(rc*G + vc*H)` is the change coin, which is created by the sender.
- `ri` and `rc` are sender's private keys.
- `(rr*G + vr*H)` is the sending coin which is **also** created by the **sender**, but `rr*G = P` is the receiver's open public key.
- `vi` is the input/spending coin amount, `vr` is the sending coin amount for the receiver, `vc` is the change amount.
- `fee` is the transaction fee for miner who validate and package this transaction.
- `offset'` is **neither** the "public excess", **nor** the public key for transaction kernel signature.

And we have the following relationships:

- `vi = vc + vr + fee`, which is used to calculate the change coin amount `vc`. 
- `offset' = (rc-ri-offset)*G + rr*G`, where `offset` is a random value selected by the sender.

The `offset'` is transmitted as part of the transaction data, but only packaged into the block header as the "total offset", which accumulate all transactions `offset'` value since the Genesis block. i.e. `offset'` is not available on the chain data.

And for the transaction signature, we reuse the name of `excess'` / "public excess" but giving a new definition for non-interactive transaction:
```
excess' = SUM(inputs)
```
Where, `SUM(inputs) = (ri*G + vi*H)` for above example with single input.

Using the signature solution with commitment as key, which only need to be executed on the sender side:

1. Select two random EC points `R1=k1*G` and `R2=k2*H`, get `R=R1+R2`.
2. Calculate `C = SUM(inputs)`, `C = (ri*G + vi*H)` for above example with single input.
3. Calculate `p = SUM(ri) mod p`, calculate `w = SUM(vi) mod p`, Where `p` is the parameter which defines the Elliptic Curve [secp256k1](https://en.bitcoin.it/wiki/Secp256k1) 's finite field Fp.
4. Calculate `e = Hash(R || C || m)`, where `m` is the signing message.
5. Calculate `k1 + e*p` as `s1`, calculate `k2 + e*w` as `s2`.
6. Done. The signature is `(R,s1,s2)`, for Pedersen Commitment `C` as key.

### A Broken Change is Needed to Support this Non-Interactive Transaction

Just for a history reason, current MimbleWimble/Grin at the time of this writing, is using the `offset` as the part of the transaction data, instead of the `offset*G`. Also the "Total Kernel Offset" in the block header is a pure number in the Elliptic Curve secp256k1 finite field Fp, instead of an Elliptic Curve point.

To support this Non-Interactive Transaction solution in the future, MimbleWimble/Grin need a broken change for this `offset`, i.e. a hard fork will be needed.


















