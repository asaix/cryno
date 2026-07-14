package cryno

import (
	"crypto/md5"
	crand "crypto/rand"
	"encoding/binary"
	"errors"
	"math/rand"
)

func pad(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize

	padBytes := make([]byte, padding)
	for row := range padBytes {
		padBytes[row] = byte(padding)
	}

	return append(data, padBytes...)
}

func unpad(data []byte) ([]byte, error) {
    if len(data) == 0 {
        return nil, errors.New("empty data")
    }

    padding := int(data[len(data)-1])

    if padding == 0 || padding > len(data) {
        return nil, errors.New("invalid padding")
    }

    for _, b := range data[len(data)-padding:] {
        if int(b) != padding {
            return nil, errors.New("invalid padding")
        }
    }

    return data[:len(data)-padding], nil
}

func rowShift3(row *[3]byte, shift int) (error) {
    shift %= 3

    switch shift {
    case 0:
        return nil
    case 1:
        row[0], row[1], row[2] = row[2], row[0], row[1]
    case 2:
        row[0], row[1], row[2] = row[1], row[2], row[0]
    }

    return nil
}

func colShift3(col *[3]byte, shift int) (error) {
    shift %= 3

    switch shift {
    case 0:
        return nil
    case 1:
        col[0], col[1], col[2] = col[2], col[0], col[1]
    case 2:
        col[0], col[1], col[2] = col[1], col[2], col[0]
    }

    return nil
}

func sTransform(data []byte, sbox [256]byte) []byte {
    out := make([]byte, len(data))

    for i := range data {
        out[i] = sbox[data[i]]
    }

    return out
}

func Encrypt(plaintext []byte, key []byte) ([]byte, error) {
    if len(key) == 0 {
        return nil, errors.New("key cannot be empty")
    }

    iv := make([]byte, 9)
    if _, err := crand.Read(iv); err != nil {
        return nil, err
    }

    keyHash := md5.Sum(key)
    seed := binary.BigEndian.Uint64(keyHash[:8])
    rng := rand.New(rand.NewSource(int64(seed)))

    var sbox [256]byte
    perm := rng.Perm(256)
    for i := 0; i < 256; i++ {
        sbox[i] = byte(perm[i])
    }

	var padded []byte = pad(plaintext, 9)
    padded = sTransform(padded, sbox)

    var ciphertext = make([]byte, len(padded))

    var previousSeq [9]byte
    copy(previousSeq[:], iv[:])
	
    for i := 0; i < len(padded); i += 9 {
        block := padded[i : i+9]

        for j := range block {
            block[j] ^= previousSeq[j]
        }


        var grid [3][3]byte
        for row:=0; row<3; row++ {
            for col:=0; col<3; col++ {
                grid[row][col] = block[row*3+col]

            }
        }
        
        for row := 0; row < 3; row++ {
            if err := rowShift3(&grid[row], row + 1); err != nil {
                return nil, err
            }
        }

        for col := 0; col < 3; col++ {
            colData := [3]byte{grid[0][col], grid[1][col], grid[2][col]}
            if err := colShift3(&colData, col + 1); err != nil {
                return nil, err
            }
            grid[0][col], grid[1][col], grid[2][col] = colData[0], colData[1], colData[2]
        }

        var seq [9]byte = [9]byte{
            grid[0][0], grid[0][1], grid[0][2],
            grid[1][0], grid[1][1], grid[1][2],
            grid[2][0], grid[2][1], grid[2][2],
        }

        for j := range seq {
            seq[j] ^= key[j%len(key)]
        }

        copy(ciphertext[i:i+9], seq[:])
        copy(previousSeq[:], seq[:])


    }

    

    return append(iv, ciphertext...), nil
}

func Decrypt(ciphertext []byte, key []byte) ([]byte, error) {
    if len(key) == 0 {
        return nil, errors.New("key cannot be empty")
    }
    if len(ciphertext) < 9 || (len(ciphertext)-9) % 9 != 0 {
        return nil, errors.New("invalid ciphertext length")
    }

    iv := ciphertext[:9]
    ciphertext = ciphertext[9:]
    
    keyHash := md5.Sum(key)
    seed := binary.BigEndian.Uint64(keyHash[:8])
    rng := rand.New(rand.NewSource(int64(seed)))
    
    var sbox [256]byte
    perm := rng.Perm(256)
    for i := 0; i < 256; i++ {
        sbox[i] = byte(perm[i])
    }

    var invSbox [256]byte
    for i := 0; i < 256; i++ {
        invSbox[sbox[i]] = byte(i)
    }    

    var grid[3][3]byte
    var plaintext = make([]byte, len(ciphertext))
    
    var block [9]byte
    var previousSeq [9]byte
    copy(previousSeq[:], iv[:])

    for i := 0; i < len(ciphertext); i += 9 {
        copy(block[:], ciphertext[i:i+9])


        for j := range block {
            block[j] ^= key[j%len(key)]
        }

        for row := 0; row < 3; row++ {
            for col := 0; col < 3; col++ {
                grid[row][col] = block[row*3+col]
            }
        }
        
        for col := 0; col < 3; col++ {
            colData := [3]byte{grid[0][col], grid[1][col], grid[2][col]}
            if err := colShift3(&colData, (2-col)%3); err != nil {
                return nil, err
            }
            grid[0][col], grid[1][col], grid[2][col] = colData[0], colData[1], colData[2]
        }
        for row := 0; row < 3; row++ {
            if err := rowShift3(&grid[row], (2-row)%3); err != nil {
                return nil, err
            }
        }

        var seq [9]byte = [9]byte{
            grid[0][0], grid[0][1], grid[0][2],
            grid[1][0], grid[1][1], grid[1][2],
            grid[2][0], grid[2][1], grid[2][2],
        }

        for j := range seq {
            seq[j] ^= previousSeq[j]
        }
        seqTransformed := sTransform(seq[:], invSbox)
       
        copy(plaintext[i:i+9], seqTransformed[:])
        copy(previousSeq[:], ciphertext[i:i+9])


    }
    
    unPadded, unPadErr := unpad(plaintext)
    if unPadErr != nil {
        return nil, unPadErr
    }
    

    return unPadded, nil
    
}