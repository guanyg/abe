package verifier

import (
	"crypto/sha256"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// ABEOutsourcingVerify is a precompiled contract used in the verification process of the scheme.
type ABEOutsourcingVerify struct{}

var secp256k1N *big.Int
var aMod *big.Int

func init() {
	secp256k1N, _ = new(big.Int).SetString("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16)
	aMod, _ = new(big.Int).SetString("8780710799663312522437781984754049815806883199414208211028653399266475630880222957078625179422662221423155858769582317459277713367317481324925129998224791", 10)
}

// RequiredGas returns the gas required to execute the pre-compiled contract.
func (e *ABEOutsourcingVerify) RequiredGas(input []byte) uint64 {
	return 5000
	// return ABEOutsourcingVerifyBaseGas + uint64(len(input)/192)*ABEOutsourcingVerifyPerPointGas
}

// Run is the entrance of the pre-compiled contract.
func (e *ABEOutsourcingVerify) Run(input []byte) ([]byte, error) {
	var (
		ct1, ct2, ct3, ct4 *quadraticEl
		offset             = uint64(0)
	)

	ct3, offset = loadQuadraticEl(input, offset)
	ct4, offset = loadQuadraticEl(input, offset)
	ct1, offset = loadQuadraticEl(input, offset)
	ct2, offset = loadQuadraticEl(input, offset)

	fmt.Printf("cx1 = %02x, %02x\n", ct1.x, ct1.y)
	fmt.Printf("cx2 = %02x, %02x\n", ct2.x, ct2.y)
	fmt.Printf("cx3 = %02x, %02x\n", ct3.x, ct3.y)
	fmt.Printf("cx4 = %02x, %02x\n", ct4.x, ct4.y)

	v := ct3.mul(ct3, ct2).mul(ct3, ct4.mul(ct4, ct1).inv())

	fmt.Printf("v = %02x, %02x\n", v.x, v.y)

	b := v.getBytes()
	hasher := sha256.New()
	hasher.Write(b)
	b = hasher.Sum(nil)

	sk := new(big.Int).SetBytes(b)
	sk.Mod(sk, secp256k1N)
	privateKey := crypto.ToECDSAUnsafe(sk.Bytes())

	addr := crypto.PubkeyToAddress(privateKey.PublicKey)

	fmt.Printf("%02x\n", addr[:])
	return addr[:], nil
}

type quadraticEl struct {
	x *big.Int
	y *big.Int
}

func (r *quadraticEl) equal(e *quadraticEl) bool {
	return r == e || (r.x.Cmp(e.x) == 0 && r.y.Cmp(e.y) == 0)
}

func (r *quadraticEl) square(e *quadraticEl) *quadraticEl {
	return r.mul(e, e)
}

func (r *quadraticEl) mul(o1, o2 *quadraticEl) *quadraticEl {
	e0 := new(big.Int).Add(o1.x, o1.y)
	e0.Mod(e0, aMod)
	e1 := new(big.Int).Add(o2.x, o2.y)
	e1.Mod(e1, aMod)
	e2 := new(big.Int).Mul(e0, e1)
	e2.Mod(e2, aMod)

	e0.Mul(o1.x, o2.x)
	e0.Mod(e0, aMod)
	e1.Mul(o1.y, o2.y)
	e1.Mod(e1, aMod)

	r.x.Sub(e0, e1)
	r.x.Mod(r.x, aMod)
	r.y.Sub(e2, e0)
	r.y.Mod(r.y, aMod)
	r.y.Sub(r.y, e1)
	r.y.Mod(r.y, aMod)
	return r
}

func (r *quadraticEl) pow(e *big.Int) *quadraticEl {
	if e.BitLen() == 0 {
		r.x = big.NewInt(1)
		r.y = big.NewInt(0)
	} else if e.BitLen() > 1 {
		word := 0
		wbits := uint(0)

		k := optimalPowWindowSize(e)
		lookup := r.buildPowWindow(k)
		inword := false
		result := &quadraticEl{big.NewInt(1), big.NewInt(0)}

		for s := uint(e.BitLen() - 1); s != ^uint(0); s-- {
			result.square(result)
			bit := testBits(e, s)
			if inword || bit != 0 {
				if !inword {
					inword = true
					word = 1
					wbits = 1
				} else {
					word = (word << 1) + bit
					wbits++
				}

				if wbits == k || s == 0 {
					result.mul(result, lookup[word])
					inword = false
				}
			}
		}

		r.x = result.x
		r.y = result.y
	}

	return r
}

func (r *quadraticEl) inv() *quadraticEl {
	x, y := new(big.Int), new(big.Int)
	x.Mul(r.x, r.x)
	x.Mod(x, aMod)
	y.Mul(r.y, r.y)
	y.Mod(y, aMod)
	x.Add(x, y)
	x.Mod(x, aMod)
	x.ModInverse(x, aMod)

	r.x = r.x.Mul(x, r.x)
	x.Sub(aMod, x)
	r.y = r.y.Mul(r.y, x)
	return r
}

func (r *quadraticEl) getBytes() []byte {
	return append(r.x.Bytes()[:], r.y.Bytes()[:]...)
}

var (
	one = &quadraticEl{big.NewInt(1), big.NewInt(0)}
)

func (r *quadraticEl) buildPowWindow(k uint) []*quadraticEl {
	if k < 1 {
		return nil
	}
	lookupSize := 1 << k
	ret := make([]*quadraticEl, lookupSize)
	ret[0] = one

	for i := 1; i < lookupSize; i++ {
		ret[i] = newQuadraticEl().mul(ret[i-1], r)
	}
	return ret
}

var (
	tba, tbb = getTestBitsParam()
)

func getTestBitsParam() (uint, uint) {
	if ^uint(0)>>32 == 0 {
		return 5, 0x1f
	}
	return 6, 0x3f
}

func testBits(e *big.Int, n uint) int {
	if (e.Bits()[n>>tba] & (1 << (n & tbb))) != 0 {
		return 1
	}
	return 0
}

func optimalPowWindowSize(e *big.Int) uint {
	var ebl = e.BitLen()
	if ebl > 9065 {
		return 8
	} else if ebl > 3529 {
		return 7
	} else if ebl > 1324 {
		return 6
	} else if ebl > 474 {
		return 5
	} else if ebl > 157 {
		return 4
	} else if ebl > 47 {
		return 3
	} else {
		return 2
	}
}

func loadQuadraticEl(data []byte, offset uint64) (*quadraticEl, uint64) {
	xBytes, offset := loadBytes(data, offset)
	yBytes, offset := loadBytes(data, offset)

	return &quadraticEl{
		new(big.Int).SetBytes(xBytes),
		new(big.Int).SetBytes(yBytes),
	}, offset
}

func loadBytes(data []byte, offset uint64) ([]byte, uint64) {
	len := new(big.Int).SetBytes(data[offset : offset+32]).Uint64()
	offset += 32

	return getData(data, offset, len), offset + len
}

func newQuadraticEl() *quadraticEl {
	return &quadraticEl{
		new(big.Int),
		new(big.Int),
	}
}

// getData returns a slice from the data based on the start and size and pads
// up to size with zero's. This function is overflow safe.
func getData(data []byte, start uint64, size uint64) []byte {
	length := uint64(len(data))
	if start > length {
		start = length
	}
	end := start + size
	if end > length {
		end = length
	}
	return common.RightPadBytes(data[start:end], int(size))
}
