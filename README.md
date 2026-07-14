## cryno

Hobby cipher made in Go.

This cipher isn't meant for any serious use as it is vulnerable to advanced attacks, and is slower than AES when AES-NI chips are used (although faster without). However, it does have a lot of important features that allow the output to be less predictable and avoid repeating patterns, and cannot be trivially broken without significant analysis of the ciphertext using advanced attack methods.


**Has**

- Confusion via key-derived substitution box (S-Box)
- Diffusion via 3x3 grid row and column shuffling
- Cross-block diffusion via CBC chaining with a random IV
- Cyclic key XOR mixing
- PKCS#7 padding
- Fully invertible pipeline

**Lacks**

- Round key scheduling (only a single round is applied per block)
- Authentication / integrity checks
- Non-linear S-box that is resistant to linear and differential cryptanalysis
- Resistance to side-channel attacks (eg. timing)

**Sample Output**

The patterns in the plaintext are not reflected in the ciphertext.
```
data: WOOBALNOOBANOOOOOOOOOOOOOOOOOOOOOOOOO
key: cog
encrypted: 4ddc25192afce9944e3e07a75ae73680ba35ff45a970c92198194ee7523ed66a0bb68c35c9782941ffad15944e8632efba0bd66cbad9
decrypted: WOOBALNOOBANOOOOOOOOOOOOOOOOOOOOOOOOO
```


### Algorithm

#### Encryption

1. Randomly generate 9-byte IV
2. Use the first 8 bytes of the MD5 hash of the key as a seed to generate the S-box
3. Pad the plaintext to a length which is a multiple of 9 bytes (the block size) using PKCS#7
4. Substitute bytes using the S-box
5. Set previous block to the generated IV, and iterate through 9 bytes (a block) at a time. For each iteration:
   1. XOR each byte of the block with the byte at the same position in the previous block.
   2. Lay the bytes out in a grid and shuffle the rows and columns (see [Grid Shuffling](#grid-shuffling))
   3. Extract the sequence of bytes from the grid in row-major order (L2R each row before moving on to the start of the next row)
   4. XOR each byte in the sequence with the key byte at that position modulo the length of the key. `seq[j] ^= key[j%len(key)]`
   5. Set the new "previous block" to this ciphertext and repeat, appending the block ciphertext to the final ciphertext array each time.
6. Prepend the IV to the complete ciphertext and return.

#### Decryption

1. Split the 9-byte IV off the front of the ciphertext
2. Use the first 8 bytes of the MD5 hash of the key as a seed to generate the S-box, then invert it to get the inverse S-box
3. Set previous block to the IV, and iterate through 9 bytes (a block) at a time. For each iteration:
   1. XOR each byte in the block with the key byte at that position modulo the length of the key, undoing the key XOR. `block[j] ^= key[j%len(key)]`
   2. Lay the bytes out in a grid and reverse the shuffle by rotating the columns then the rows in the opposite direction (see [Grid Shuffling](#grid-shuffling))
   3. Extract the sequence of bytes from the grid in row-major order (L2R each row before moving on to the start of the next row)
   4. XOR each byte in the sequence with the byte at the same position in the previous block, undoing the CBC chaining.
   5. Substitute the bytes back using the inverse S-box to recover the original plaintext bytes.
   6. Set the new "previous block" to the original ciphertext block (before it was modified) and repeat, appending the block plaintext to the final plaintext array each time.
4. Remove the PKCS#7 padding and return.

### API

Two functions, both taking the data and key as `[]byte`:

```go
func Encrypt(plaintext []byte, key []byte) ([]byte, error)
func Decrypt(ciphertext []byte, key []byte) ([]byte, error)
```

`Encrypt` returns the IV prepended to the ciphertext. `Decrypt` takes that output and returns the original plaintext. Both return an error on an empty key (and `Decrypt` on malformed ciphertext).

```go
ct, err := cryno.Encrypt([]byte("hello"), []byte("secret-key"))
pt, err := cryno.Decrypt(ct, []byte("secret-key"))
```

### Reference

##### Grid Shuffling

Each 9-byte block is laid out as a 3x3 grid (row-major), then rows and columns are
cyclically rotated. Rows are shifted first: row `r` is rotated right by `r+1` for all rows, then columns are shifted: `c` is rotated
right by `c+1` (a shift of 3 wraps back to no change).

Using `b0`..`b8` for the byte positions within the block:

```
      Before              After row shift        After column shift
   b0  b1  b2              b2  b0  b1              b6  b5  b1
   b3  b4  b5     -->      b4  b5  b3     -->      b2  b7  b3
   b6  b7  b8              b6  b7  b8              b4  b0  b8
```

Row shifts: row 0 right by 1, row 1 right by 2, row 2 unchanged.
Column shifts: col 0 right by 1, col 1 right by 2, col 2 unchanged.
