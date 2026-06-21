(* bigint.sig

   Arbitrary-precision signed integers in pure Standard ML.

   The representation is sign-magnitude over a base-2^32 limb vector
   (little-endian).  Multiplication uses Karatsuba above a small cutoff and
   schoolbook below it; division is binary long division; GCD is the binary
   (Stein) algorithm; modular exponentiation is square-and-multiply; and
   primality testing is deterministic Miller-Rabin over fixed witness bases.

   The abstract type is named [int] so the structure reads like an integer
   module.  Parameters whose natural type is the host machine integer are
   given as [Int.int]; every other [int] in this signature is the
   arbitrary-precision type.  String output follows the Basis convention of a
   leading "~" for negatives, so [toString] agrees character-for-character
   with [IntInf.toString]. *)

signature BIGINT =
sig
  type int

  (* ---- Conversions ---- *)

  (* Inject a host integer (handles the most-negative value). *)
  val fromInt   : Int.int -> int
  (* Project to a host integer; NONE when out of [Int] range. *)
  val toInt     : int -> Int.int option
  (* Parse a base-10 numeral with an optional leading "~", "-" or "+".
     NONE on empty input or any non-digit. *)
  val fromString : string -> int option
  (* Base-10 numeral, "~"-prefixed when negative. *)
  val toString  : int -> string
  (* [toStringRadix r n] renders n in radix r (2 <= r <= 36) using digits
     0-9a-z, "~"-prefixed when negative.  The radix is itself an [int]. *)
  val toStringRadix : int -> int -> string

  (* ---- Arithmetic ---- *)

  val ~   : int -> int
  val +   : int * int -> int
  val -   : int * int -> int
  val *   : int * int -> int
  (* Prefix spellings of the operators above, for ergonomic qualified use. *)
  val add : int * int -> int
  val sub : int * int -> int
  val mul : int * int -> int

  (* Floored division: the remainder takes the sign of the divisor.
     Agrees with [IntInf.divMod].  Raises [Div] when the divisor is zero. *)
  val divMod  : int * int -> int * int
  (* Truncated division: the remainder takes the sign of the dividend.
     Agrees with [IntInf.quotRem].  Raises [Div] when the divisor is zero. *)
  val quotRem : int * int -> int * int

  val compare : int * int -> order
  (* The sign as a bignum: ~1, 0 or 1. *)
  val sign : int -> int
  val abs  : int -> int

  (* [pow (b, e)] is b raised to e; raises [Domain] for negative e. *)
  val pow  : int * int -> int
  (* Greatest common divisor, always non-negative. *)
  val gcd  : int * int -> int
  (* [modpow (b, e, m)] is (b^e) mod m for e >= 0 and m > 0; the result is the
     non-negative residue.  Raises [Domain] for negative e, [Div] for m <= 0. *)
  val modpow : int * int * int -> int
  (* Deterministic Miller-Rabin.  The second argument is the number of fixed
     small witness bases to try (clamped to the table size). *)
  val isProbablePrime : int * int -> bool
end
