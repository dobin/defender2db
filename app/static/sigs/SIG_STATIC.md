# STATIC signatures: what those hashes are

This is the short, no-reversing-needed explanation of a Defender `SIGNATURE_TYPE_STATIC`
record. Read this if you are looking at a STATIC signature and wondering what the numbers
mean for detection and evasion.

## The one-sentence version

A STATIC signature is a **fingerprint of a known file**: a few checksums of the file's
beginning, its end, a larger beginning window, plus the file size and usually one strong
file hash. Defender recomputes those values on the file it is scanning and compares them
to the signature. If they match, the file is treated as the known file (which may be a
detection, or a "this file is clean" verdict).

There are no byte strings, no offsets to patch, and nothing to "decode" into readable
content. It is a whole-file identity check built from hashes.

## What is actually compared

Let `N` be the file size stored in the signature.

```
0                                                                    N
|-- 4 KiB --|-------------------- ... --------------------|-- 4 KiB --|
    CRC1                       strong hash                     CRC3
|---------------- CRC2: first min(N, 64 KiB) -------------------------|
```

| Value | What it covers | Notes |
|-------|----------------|-------|
| **CRC1** | First 4 KiB of the file | Primary lookup key. Short files are zero-padded to 4 KiB. |
| **CRC2** | First `min(N, 64 KiB)` bytes | If the fingerprinted prefix `N` is 64 KiB or smaller, this covers that whole prefix (`N` bytes). |
| **CRC3** | Last 4 KiB of the first `N` bytes | For short files the window is zero-padded at the front. For "prefix" signatures this is the end of the fingerprinted range, not necessarily the real EOF. |
| **size** | `N` | Either the exact file size or a lower bound (see below). |
| **strong hash** | First `N` bytes | Usually CRC32; sometimes MD5 or SHA1; in newer formats also SHA1[:4] or SHA256. |
| **tag** (optional) | — | A trailing engine directive such as `#ClnFile`, `#ExpensiveFile`, `#FP:...`, `#PUA:...`. It changes what a match *means*, not how the bytes are hashed. |

All four checksums are CRC32 of the file's bytes (or MD5/SHA1/SHA256 for the final strong
hash). None of them are hashes of the signature itself.

These are the same values the threat view calls **Partial CRC 1 / 2 / 3**, plus the size,
the strong hash and the "Prefix match" / "Exact size" mode.

## Flags

`flags` is a 16-bit field, but only four bits are used:

| Bits | Mask | Meaning |
|---|---:|---|
| 0 | `0x0001` | Prefix match: the file may be larger than `N` (only the first `N` bytes are fingerprinted). |
| 1–11 | `0x0ffe` | Unused; zero in observed records. |
| 12–14 | `0x7000` | Strong-hash algorithm. |
| 15 | `0x8000` | Unused; zero in observed records. |

The algorithm value (`flags & 0x7000`) is:

| `flags & 0x7000` | Strong hash |
|---:|---|
| `0x0000` | MD5 |
| `0x1000` | SHA-1 |
| `0x2000` | CRC32 |
| `0x3000` | SHA-1, first 4 bytes |
| `0x4000` | SHA-256 |
| `0x5000`–`0x7000` | not observed |

The common combinations are therefore:

* `0x2001` — CRC32 + prefix match (the most common value).
* `0x2000` — CRC32 + exact size.
* `0x1001` — SHA-1 + prefix match.
* `0x1000` — SHA-1 + exact size.
* `0x0001` — MD5 + prefix match (MD5 has no algorithm bit, so the high nibble is zero).

So `0x2001` and `0x2000` are the same CRC32 signature format; `0x2001` is literally
`0x2000 | 0x0001`. The only difference is the **prefix-match bit**. `0x2001` accepts a
longer file, `0x2000` requires the exact size.
Bits outside `0x7001` should be zero; if they are set, the record uses an extension this
explanation does not cover.

## Exact size vs. "prefix" size

This is the most important nuance for evasion.

* **Exact-size record** — the scanned file must be exactly `N` bytes. Appending or
  truncating even one byte makes the file not match.
* **Prefix record** — the record only describes the first `N` bytes of a file. The scanned
  file may be **larger** than `N`. Everything after byte `N` is outside the fingerprint:
  it is not included in CRC1, CRC2, CRC3 or the strong hash.

Only the bytes matter: file name, path, filesystem timestamps and other metadata are
irrelevant. Renaming or moving a file does nothing to a STATIC match.

In the current signature database roughly **91% of STATIC records are prefix records**.
That means appending data to a file is *not* a general evasion technique: most records
will still match. Conversely, for the ~9% exact-size records, appending a single byte is
enough to stop a match.

## What a match requires

Defender effectively does:

1. Is the size acceptable? (`== N` for exact records; `>= N` for prefix records.)
2. Does CRC1 of the file's first 4 KiB match?
3. Does CRC2 of the beginning (up to 64 KiB) match?
4. Does CRC3 of the last 4 KiB of the `N`-byte prefix match?
5. Does the strong hash of the `N`-byte prefix match?
6. If there is a tag, apply its meaning (`#ClnFile` = clean, `#PUA:...` = classify,
   `#ExpensiveFile` = perf hint, and so on).

A failure at any step means "not this signature". CRC1 is special: it is used to find
candidate records in the first place, so a different first 4 KiB usually means Defender
never even reaches the strong-hash check.

## How hard is it to forge or evade?

### Breaking a match

The cheapest evasion is usually **one harmless change in the first 4 KiB**. That changes
CRC1, so the signature's primary lookup no longer finds the file. This is why trivial
mutations (a different PE timestamp, a padding byte, a comment in a script) can be enough
to fall off a known-file signature.

Other cases:

| Change to the file | Exact-size record | Prefix record |
|---|---|---|
| Change a byte in the first 4 KiB | Evades (CRC1 changes) | Evades, if inside the `N`-byte prefix |
| Change a byte in the middle | Breaks the strong hash | Breaks the strong hash (inside `N`) |
| Change a byte in the last 4 KiB of `N` | Breaks CRC3 | Breaks CRC3 (inside `N`) |
| Append bytes at EOF | **Evades** (size changes) | **Does not evade** (outside `N`) |
| Truncate below `N` | Evades (size changes) | Evades (now smaller than `N`) |
| Prepend bytes | Evades (CRC1 shifts) | Evades (CRC1 shifts) |

For prefix records, "change" means inside the `N`-byte prefix. Bytes after `N` are not
covered by any of the four hashes.

The middle of the fingerprinted prefix is only covered by the final strong hash. That
matters for the next section.

### Forging a matching file

Most STATIC records (about **96%** in the current DB) use **CRC32 as the strong hash**.
The three window checksums are CRC32 as well. CRC32 is linear and not collision-resistant,
so a determined attacker with CRC math can in principle modify bytes inside the prefix
while keeping all four CRC32 values intact (and for a prefix record, appending bytes after
`N` needs no work at all). It is not trivial to do by hand, but it is not a cryptographic
barrier either.

About **4%** of records use SHA1 (and a handful use MD5). For those, changing any byte
inside the fingerprinted prefix breaks the hash, and finding a collision is a real
research problem rather than a quick patch. SHA256 records are supported by the format but
are not present in the current database.

Keep in mind the windows overlap in coverage: patching the middle avoids the window CRCs
but not the strong hash; patching near the start or end hits the window CRCs too. A valid
forgery must satisfy all of them at once.

### Abusing the record semantics

Some STATIC records are not detections at all:

* `#ClnFile` / `#Clean` — matching marks the file clean/friendly (sometimes for a limited
  time).
* `#ExpensiveFile` — matching tells the engine the file is expensive to scan (performance
  hint).
* `#FP:<family>` — false-positive suppression.
* `#PUA:...`, `#Trojan:...` — matching attaches that classification.
* `#Exclusion`, `#Exclude` — static-match exclusions.

So a STATIC record can be a "known bad", a "known good", a performance marker, or an
exclusion. The hashes are the same in all cases; the trailing tag decides what happens
after a match.

## Practical summary

* Think of a STATIC signature as: **"size + CRC of the first 4 KiB + CRC of the beginning
  (up to 64 KiB) + CRC of the end + one strong hash of the first N bytes."**
* If the fingerprinted prefix `N` is at most 64 KiB, the "beginning" checksum covers the
  whole prefix.
* Any difference in the covered prefix breaks the match. The first 4 KiB is the easiest
  and most reliable place to introduce a difference.
* Appending data only defeats the exact-size minority (~9%); prefix records ignore
  everything after byte `N`.
* The strong hash is usually only CRC32, so the whole signature is a set of weak
  checksums; cryptographic strength only appears with the MD5/SHA1/SHA256 variants.
* A trailing word like `#ClnFile` or `#PUA:...` is not part of the fingerprint; it tells
  Defender what a match means.

One caveat: evading a STATIC record only means falling off *that* fingerprint. Defender
has many unrelated signature types (byte patterns, PE/script strings, behaviour trees,
KCRCE-style hashes, and so on), and changing a file can also introduce new detections.
STATIC is one layer of the stack, not the whole detection.
