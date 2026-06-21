# sml-asn1

[![CI](https://github.com/sjqtentacles/sml-asn1/actions/workflows/ci.yml/badge.svg)](https://github.com/sjqtentacles/sml-asn1/actions/workflows/ci.yml)

ASN.1 **DER** (Distinguished Encoding Rules) encoder/decoder for Standard ML:
pure, deterministic, and byte-identical under [MLton](http://mlton.org/) and
[Poly/ML](https://www.polyml.org/).

DER is the canonical, length-prefixed binary form underneath X.509
certificates, PKCS, and most cryptographic on-the-wire formats. `sml-asn1`
covers the common subset — `BOOLEAN`, `INTEGER`, `OCTET STRING`, `BIT STRING`,
`NULL`, `OBJECT IDENTIFIER`, `UTF8String`, `PrintableString`, `SEQUENCE`,
`SET`, and explicit context tags — and carries arbitrary-precision `INTEGER`
values with the vendored [`sml-bigint`](https://github.com/sjqtentacles/sml-bigint),
so serial numbers and moduli far beyond a host `int` round-trip exactly.

Everything is pure Standard ML over the Basis library: no FFI, threads, clock,
or RNG, so a given value always produces the same bytes. Encoded values are
plain `string`s of bytes (one byte per `char`, codepoints 0..255).

## Why DER is nice to encode

Every value has exactly **one** valid encoding, so the round-trip is a
genuine identity:

```
encode : der -> string      (* total on representable values *)
decode : string -> der      (* strict: rejects anything non-canonical *)
```

`decode` is deliberately picky — it rejects indefinite lengths, non-minimal
lengths, non-minimal `INTEGER`/`OID` encodings, primitive types carrying the
constructed bit, high-tag-number form, and trailing bytes — so
`decode (encode x) = x` and `encode (decode b) = b` both hold.

## API

```sml
structure Asn1 : sig
  datatype der =
      Bool of bool
    | Int of BigInt.int          (* arbitrary precision *)
    | Bytes of string            (* OCTET STRING *)
    | BitString of string        (* whole-octet bit string, 0 unused bits *)
    | Null
    | Oid of int list            (* >= 2 arcs *)
    | Utf8 of string             (* UTF8String *)
    | PrintableString of string
    | Seq of der list            (* SEQUENCE *)
    | Set of der list            (* SET, encoded in the given order *)
    | Context of int * der       (* explicit context-specific tag, 0..30 *)

  exception Asn1 of string

  val encode    : der -> string
  val decode    : string -> der          (* raises Asn1 on malformed input *)
  val decodeOpt : string -> der option   (* NONE instead of raising *)
end
```

## How it works

| Field | Encoding |
| --- | --- |
| Identifier octet | class (2 bits) + constructed bit (`0x20`) + tag number (low 5 bits) |
| Length | DEFINITE: short form `< 128`, else long form `0x80 \| n` + `n` minimal big-endian octets |
| `INTEGER` | minimal two's complement, big-endian, no redundant `00`/`FF` leading byte |
| `OBJECT IDENTIFIER` | first two arcs combined as `40*a0 + a1`, each subidentifier base-128 with continuation bits |
| `SEQUENCE` / `SET` | constructed; contents are the concatenated encodings of the elements |
| `Context (n, d)` | explicit (constructed) context tag `n` wrapping the full encoding of `d` |

`INTEGER` arithmetic (the `2^k` masks and base-256 digit extraction) is done
with `sml-bigint`, so values of any size are exact.

### Reference encodings

```
INTEGER 0       -> 02 01 00
INTEGER 127     -> 02 01 7F
INTEGER 128     -> 02 02 00 80
INTEGER ~128    -> 02 01 80
BOOLEAN true    -> 01 01 FF
BOOLEAN false   -> 01 01 00
NULL            -> 05 00
OID 1.2.840.113549.1.1.11 (sha256WithRSAEncryption)
                -> 06 09 2A 86 48 86 F7 0D 01 01 0B
```

### Example

```sml
val msg =
  Asn1.Seq
    [ Asn1.Context (0, Asn1.Int (BigInt.fromInt 2))           (* [0] version *)
    , Asn1.Int (valOf (BigInt.fromString "123456789012345678901234567890"))
    , Asn1.Oid [1, 2, 840, 113549, 1, 1, 11]                  (* sha256WithRSA *)
    , Asn1.PrintableString "example.com"
    , Asn1.Bool true
    , Asn1.Null ]

val der  = Asn1.encode msg          (* 51-byte string, starts 30 31 A0 03 ... *)
val back = Asn1.decode der          (* structurally equal to msg *)
```

`examples/demo.sml` builds this value, prints the bytes as hex, and decodes
them back; `make example` builds and runs it.

## Build & test

Requires [MLton](http://mlton.org/) and/or [Poly/ML](https://polyml.org/).

```sh
make test        # build + run the suite under MLton
make test-poly   # run the suite under Poly/ML (use-and-run)
make all-tests   # both
make example     # build + run examples/demo.sml
make clean
```

## Installing with smlpkg

```sh
smlpkg add github.com/sjqtentacles/sml-asn1
smlpkg sync
```

Reference `src/asn1.mlb` from your own `.mlb` (it pulls in the vendored
`sml-bigint`), or, under Poly/ML, `use` the sources in dependency order
(`bigint.sig`, `bigint.sml`, `asn1.sig`, `asn1.sml`) — see the `test-poly`
target in the `Makefile`.

## Layout

Layout B (dependent): own sources live in `src/`; `sml-bigint` is vendored
under `lib/` and loaded first.

```
sml.pkg                                       smlpkg manifest
Makefile                                      MLton + Poly/ML targets
.github/workflows/ci.yml                      CI: MLton + Poly/ML
src/
  asn1.sig / asn1.sml   DER encoder/decoder
  asn1.mlb              public basis (pulls in the vendored sml-bigint)
lib/github.com/sjqtentacles/sml-bigint/       vendored dependency
examples/
  demo.sml              encode a SEQUENCE, print hex, decode back
  sources.mlb
test/
  harness.sml           shared assertion harness
  test_asn1.sml         reference vectors + round-trips (91 checks)
  entry.sml / main.sml
```

## Tests

91 deterministic checks: the reference DER vectors above, minimal two's
complement `INTEGER` (including negatives and values past 64 / 128 / 200
bits), `OBJECT IDENTIFIER` arc combination and base-128 subidentifiers,
`OCTET`/`UTF8`/`PrintableString`/`BIT STRING`, nested `SEQUENCE`/`SET`/context
tags, short- and long-form lengths (200- and 300-byte contents), full
`decode (encode x) = x` round-trips, and a battery of malformed inputs that
`decode` must reject. Run `make all-tests` to verify identical output under
both compilers.

## License

MIT — see [LICENSE](LICENSE).
