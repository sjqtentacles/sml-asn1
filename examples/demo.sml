(* demo.sml

   A small command-line demo for sml-asn1: builds a SEQUENCE of mixed ASN.1
   values (including an arbitrary-precision INTEGER carried by sml-bigint),
   DER-encodes it, prints the bytes as hex, then decodes them back and shows
   the round-trip is exact. *)

structure A = Asn1
structure B = BigInt

fun line s = print (s ^ "\n")

(* uppercase, space-separated hex, the way DER bytes are written in specs *)
fun toHex s =
  let
    val digits = "0123456789ABCDEF"
    fun hx c =
      let val n = Char.ord c
      in String.implode [String.sub (digits, n div 16), String.sub (digits, n mod 16)] end
  in
    String.concatWith " " (List.map hx (String.explode s))
  end

(* structural equality (BigInt.int is abstract, so [der] is not an eqtype) *)
fun derEq (a, b) =
  case (a, b) of
    (A.Bool x, A.Bool y) => x = y
  | (A.Int x, A.Int y) => B.compare (x, y) = EQUAL
  | (A.Bytes x, A.Bytes y) => x = y
  | (A.BitString x, A.BitString y) => x = y
  | (A.Null, A.Null) => true
  | (A.Oid x, A.Oid y) => x = y
  | (A.Utf8 x, A.Utf8 y) => x = y
  | (A.PrintableString x, A.PrintableString y) => x = y
  | (A.Seq x, A.Seq y) => listEq (x, y)
  | (A.Set x, A.Set y) => listEq (x, y)
  | (A.Context (tx, dx), A.Context (ty, dy)) => tx = ty andalso derEq (dx, dy)
  | _ => false
and listEq ([], []) = true
  | listEq (x :: xs, y :: ys) = derEq (x, y) andalso listEq (xs, ys)
  | listEq _ = false

val () = line "sml-asn1 demo"
val () = line "============="
val () = line ""

(* A made-up certificate-ish SEQUENCE: version, a big serial number, the
   sha256WithRSAEncryption OID, a printable common name, and a flag. *)
val bigSerial = valOf (B.fromString "123456789012345678901234567890")

val msg =
  A.Seq
    [ A.Context (0, A.Int (B.fromInt 2))                  (* [0] version v3 *)
    , A.Int bigSerial                                     (* serial (> 64-bit) *)
    , A.Oid [1, 2, 840, 113549, 1, 1, 11]                 (* sha256WithRSA *)
    , A.PrintableString "example.com"
    , A.Bool true
    , A.Null ]

val der = A.encode msg

val () = line "value:"
val () = line "  SEQUENCE { [0] INTEGER 2, INTEGER 123456789012345678901234567890,"
val () = line "             OID 1.2.840.113549.1.1.11, PrintableString \"example.com\","
val () = line "             BOOLEAN true, NULL }"
val () = line ""
val () = line ("encoded (" ^ Int.toString (String.size der) ^ " bytes):")
val () = line ("  " ^ toHex der)
val () = line ""

val back = A.decode der
val () = line ("decoded serial = " ^
               (case back of
                  A.Seq (_ :: A.Int n :: _) => B.toString n
                | _ => "?"))
val () = line ("round-trip ok  = " ^ Bool.toString (derEq (back, msg)))
val () = line ("re-encode ok   = " ^ Bool.toString (A.encode back = der))
