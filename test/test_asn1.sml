(* test_asn1.sml

   Deterministic test suite for sml-asn1.  Reference encodings are checked
   against the DER specification (X.690): INTEGER minimal two's complement,
   BOOLEAN, NULL, OBJECT IDENTIFIER, OCTET STRING, SEQUENCE/SET, long-form
   lengths, and full encode/decode round-trips.  Output is plain text and
   identical across MLton and Poly/ML. *)

structure Asn1Tests =
struct

  open Asn1
  structure B = BigInt

  (* ---- helpers ---- *)

  (* Uppercase, space-separated hex, e.g. "02 01 00" -- matches the way DER
     vectors are written in specs and RFCs. *)
  fun toHex s =
    let
      val digits = "0123456789ABCDEF"
      fun hx c =
        let val n = Char.ord c
        in String.implode [String.sub (digits, n div 16), String.sub (digits, n mod 16)] end
    in
      String.concatWith " " (List.map hx (String.explode s))
    end

  fun bigDec str = valOf (B.fromString str)

  (* structural equality on [der] (BigInt.int is abstract, so [der] is not an
     equality type and we compare INTEGER values via BigInt.compare) *)
  fun derEq (a, b) =
    case (a, b) of
      (Bool x, Bool y) => x = y
    | (Int x, Int y) => B.compare (x, y) = EQUAL
    | (Bytes x, Bytes y) => x = y
    | (BitString x, BitString y) => x = y
    | (Null, Null) => true
    | (Oid x, Oid y) => x = y
    | (Utf8 x, Utf8 y) => x = y
    | (PrintableString x, PrintableString y) => x = y
    | (Seq x, Seq y) => listEq (x, y)
    | (Set x, Set y) => listEq (x, y)
    | (Context (tx, dx), Context (ty, dy)) => tx = ty andalso derEq (dx, dy)
    | _ => false
  and listEq ([], []) = true
    | listEq (x :: xs, y :: ys) = derEq (x, y) andalso listEq (xs, ys)
    | listEq _ = false

  (* assert encode v hexes to [expected] *)
  fun checkEnc name (expected, v) =
    Harness.checkString name (expected, toHex (encode v))

  (* assert decode (encode v) is structurally v, and re-encodes identically *)
  fun checkRoundTrip name v =
    let
      val enc = encode v
      val back = decode enc
    in
      Harness.checkBool (name ^ " (decode=value)") (true, derEq (back, v));
      Harness.checkString (name ^ " (re-encode)") (toHex enc, toHex (encode back))
    end

  (* ---- INTEGER ---- *)
  fun integers () =
    let
      val () = Harness.section "INTEGER (minimal two's complement)"
      val () = checkEnc "0"    ("02 01 00", Int (B.fromInt 0))
      val () = checkEnc "127"  ("02 01 7F", Int (B.fromInt 127))
      val () = checkEnc "128"  ("02 02 00 80", Int (B.fromInt 128))
      val () = checkEnc "256"  ("02 02 01 00", Int (B.fromInt 256))
      val () = checkEnc "~1"   ("02 01 FF", Int (B.fromInt ~1))
      val () = checkEnc "~128" ("02 01 80", Int (B.fromInt ~128))
      val () = checkEnc "~129" ("02 02 FF 7F", Int (B.fromInt ~129))
      val () = checkEnc "~256" ("02 02 FF 00", Int (B.fromInt ~256))
      (* a large (>64-bit) integer: 2^64 = 0x1 0000000000000000 *)
      val () = checkEnc "2^64" ("02 09 01 00 00 00 00 00 00 00 00",
                                Int (B.pow (B.fromInt 2, B.fromInt 64)))
      val () = List.app (fn (s, v) => checkRoundTrip ("round-trip " ^ s) (Int v))
        [ ("0", B.fromInt 0)
        , ("255", B.fromInt 255)
        , ("~255", B.fromInt ~255)
        , ("65535", B.fromInt 65535)
        , ("big+", bigDec "123456789012345678901234567890123456789")
        , ("big-", bigDec "~98765432109876543210987654321")
        , ("2^128", B.pow (B.fromInt 2, B.fromInt 128))
        , ("~(2^200)", B.~ (B.pow (B.fromInt 2, B.fromInt 200))) ]
    in () end

  (* ---- BOOLEAN / NULL ---- *)
  fun boolNull () =
    let
      val () = Harness.section "BOOLEAN and NULL"
      val () = checkEnc "true"  ("01 01 FF", Bool true)
      val () = checkEnc "false" ("01 01 00", Bool false)
      val () = checkEnc "null"  ("05 00", Null)
      val () = checkRoundTrip "true"  (Bool true)
      val () = checkRoundTrip "false" (Bool false)
      val () = checkRoundTrip "null"  Null
    in () end

  (* ---- OBJECT IDENTIFIER ---- *)
  fun oids () =
    let
      val () = Harness.section "OBJECT IDENTIFIER"
      (* sha256WithRSAEncryption *)
      val () = checkEnc "1.2.840.113549.1.1.11"
                 ("06 09 2A 86 48 86 F7 0D 01 01 0B",
                  Oid [1, 2, 840, 113549, 1, 1, 11])
      (* rsaEncryption *)
      val () = checkEnc "1.2.840.113549.1.1.1"
                 ("06 09 2A 86 48 86 F7 0D 01 01 01",
                  Oid [1, 2, 840, 113549, 1, 1, 1])
      val () = checkEnc "2.5.4.3 (commonName)" ("06 03 55 04 03", Oid [2, 5, 4, 3])
      val () = checkEnc "1.2.3" ("06 02 2A 03", Oid [1, 2, 3])
      val () = checkEnc "0.39" ("06 01 27", Oid [0, 39])
      val () = checkEnc "2.100.3" ("06 03 81 34 03", Oid [2, 100, 3])
      val () = checkRoundTrip "oid sha256WithRSA" (Oid [1, 2, 840, 113549, 1, 1, 11])
      val () = checkRoundTrip "oid 2.16.840.1.101.3.4.2.1 (sha256)"
                 (Oid [2, 16, 840, 1, 101, 3, 4, 2, 1])
    in () end

  (* ---- strings / octets / bit string ---- *)
  fun strings () =
    let
      val () = Harness.section "OCTET STRING, UTF8String, PrintableString, BIT STRING"
      val () = checkEnc "octet 01 02 03" ("04 03 01 02 03",
                 Bytes (String.implode [Char.chr 1, Char.chr 2, Char.chr 3]))
      val () = checkEnc "octet empty" ("04 00", Bytes "")
      val () = checkEnc "utf8 'hi'" ("0C 02 68 69", Utf8 "hi")
      val () = checkEnc "printable 'AB'" ("13 02 41 42", PrintableString "AB")
      val () = checkEnc "bitstring 0xCAFE" ("03 03 00 CA FE",
                 BitString (String.implode [Char.chr 0xCA, Char.chr 0xFE]))
      val () = checkRoundTrip "octet" (Bytes "hello world")
      val () = checkRoundTrip "utf8"  (Utf8 "h\195\169llo")  (* "héllo" as UTF-8 bytes *)
      val () = checkRoundTrip "printable" (PrintableString "Common Name")
      val () = checkRoundTrip "bitstring" (BitString "\003\255")
    in () end

  (* ---- SEQUENCE / SET / context, nesting, long form ---- *)
  fun structured () =
    let
      val () = Harness.section "SEQUENCE / SET / Context and long-form length"
      val mixed = Seq [ Int (B.fromInt 1)
                      , Bool true
                      , Utf8 "hi"
                      , Null
                      , Oid [1, 2, 840, 113549, 1, 1, 11]
                      , Bytes "xy" ]
      (* SEQUENCE { INTEGER 1, BOOLEAN true, UTF8 "hi", NULL, OID..., OCTET "xy" } *)
      val () = checkEnc "seq mixed"
                 ("30 1B 02 01 01 01 01 FF 0C 02 68 69 05 00 "
                  ^ "06 09 2A 86 48 86 F7 0D 01 01 0B 04 02 78 79", mixed)
      val () = checkRoundTrip "seq mixed" mixed
      val () = checkEnc "empty seq" ("30 00", Seq [])
      val () = checkRoundTrip "set" (Set [Int (B.fromInt 1), Bool false])
      val () = checkRoundTrip "nested"
                 (Seq [Seq [Int (B.fromInt 7), Set [Null, Bool true]],
                       Context (0, Utf8 "ctx")])
      val () = checkEnc "context [0] explicit" ("A0 02 05 00", Context (0, Null))
      val () = checkRoundTrip "context" (Context (3, Int (B.fromInt 42)))

      (* long-form length: 200-byte OCTET STRING -> 04 81 C8 <200 bytes> *)
      val big = String.implode (List.tabulate (200, fn i => Char.chr (i mod 256)))
      val encBig = encode (Bytes big)
      val () = Harness.checkString "long-form prefix"
                 ("04 81 C8", toHex (String.substring (encBig, 0, 3)))
      val () = Harness.checkInt "long-form total size" (203, String.size encBig)
      val () = checkRoundTrip "long-form octet" (Bytes big)
      (* even longer: 300 bytes -> two length octets 01 2C *)
      val big2 = String.implode (List.tabulate (300, fn i => Char.chr (i mod 256)))
      val encBig2 = encode (Bytes big2)
      val () = Harness.checkString "long-form 2-octet prefix"
                 ("04 82 01 2C", toHex (String.substring (encBig2, 0, 4)))
      val () = checkRoundTrip "long-form octet 300" (Bytes big2)
    in () end

  (* ---- malformed input is rejected ---- *)
  fun malformed () =
    let
      val () = Harness.section "decode rejects malformed / non-DER input"
      fun bytes ns = String.implode (List.map Char.chr ns)
      val () = Harness.checkRaises "empty input" (fn () => decode "")
      val () = Harness.checkRaises "truncated length"
                 (fn () => decode (bytes [0x02]))
      val () = Harness.checkRaises "length exceeds input"
                 (fn () => decode (bytes [0x04, 0x05, 0x01, 0x02]))
      val () = Harness.checkRaises "trailing bytes"
                 (fn () => decode (bytes [0x05, 0x00, 0x00]))
      val () = Harness.checkRaises "non-minimal INTEGER 00 00"
                 (fn () => decode (bytes [0x02, 0x02, 0x00, 0x00]))
      val () = Harness.checkRaises "non-minimal INTEGER 00 7F"
                 (fn () => decode (bytes [0x02, 0x02, 0x00, 0x7F]))
      val () = Harness.checkRaises "non-minimal INTEGER FF FF"
                 (fn () => decode (bytes [0x02, 0x02, 0xFF, 0xFF]))
      val () = Harness.checkRaises "empty INTEGER" (fn () => decode (bytes [0x02, 0x00]))
      val () = Harness.checkRaises "BOOLEAN bad value"
                 (fn () => decode (bytes [0x01, 0x01, 0x01]))
      val () = Harness.checkRaises "BOOLEAN bad length"
                 (fn () => decode (bytes [0x01, 0x02, 0x00, 0xFF]))
      val () = Harness.checkRaises "NULL bad length"
                 (fn () => decode (bytes [0x05, 0x01, 0x00]))
      val () = Harness.checkRaises "non-minimal long-form length"
                 (fn () => decode (bytes [0x04, 0x81, 0x01, 0x41]))
      val () = Harness.checkRaises "indefinite length"
                 (fn () => decode (bytes [0x30, 0x80, 0x00, 0x00]))
      val () = Harness.checkRaises "high-tag-number form"
                 (fn () => decode (bytes [0x1F, 0x01, 0x00]))
      (* decodeOpt returns NONE rather than raising *)
      val () = Harness.checkBool "decodeOpt malformed -> NONE"
                 (true, not (isSome (decodeOpt (bytes [0x02]))))
      val () = Harness.checkBool "decodeOpt valid -> SOME"
                 (true, isSome (decodeOpt (encode Null)))
    in () end

  fun run () =
    ( integers ()
    ; boolNull ()
    ; oids ()
    ; strings ()
    ; structured ()
    ; malformed () )
end
