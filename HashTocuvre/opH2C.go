package h2c

import (
	"crypto"
	"errors"
	"fmt"
	"math"
	"math/big"

	C "github.com/armfazh/tozan-ecc/curve"
	GF "github.com/armfazh/tozan-ecc/field"
)

// HashToPoint
type HashToPoint interface {
	IsRandomOracle() bool          // 출력 분포가 무작위 오라클과 구별 불가능한지 여부를 반환
	Hash(in []byte) C.Point        // 바이트 문자열을 타원 곡선 상의 점으로 변환
	GetCurve() C.EllCurve          // 목표 타원 곡선을 반환
	GetHashToScalar() HashToScalar // 문자열을 스칼라 필드 원소로 해싱하는 함수를 반환
}

// HashToScalar
type HashToScalar interface {
	GetScalarField() GF.Field // 스칼라 필드를 반환
	Hash(in []byte) GF.Elt    // 바이트 문자열을 필드 원소로 변환
}

type MapToCurve interface {
	Map(GF.Elt) C.Point
}

type Expander interface {
	// Expand는 주어진 메시지를 더 긴 바이트 시퀀스로 확장
	Expand(msg []byte, n uint) []byte
}

// expanderXMD는 XMD (eXpandable Message Digest) 방식을 사용하는 Expander의 구현
type expanderXMD struct {
	id  crypto.Hash // 사용할 해시 함수의 ID
	dst []byte      // 도메인 분리 태그
}

func xor(a, b []byte) []byte {
	result := make([]byte, len(a))
	for i := range a {
		result[i] = a[i] ^ b[i]
	}
	return result
}

func (e *expanderXMD) Expand(msg []byte, n uint) []byte {
	H := e.id.New()
	bLen := uint(H.Size())
	ell := (n + (bLen - 1)) / bLen
	if ell > math.MaxUint8 || n > math.MaxUint16 || len(e.dst) > math.MaxUint8 {
		panic(errors.New("requested too many bytes"))
	}

	zPad := make([]byte, H.BlockSize())
	libStr := []byte{0, 0}
	libStr[0] = byte((n >> 8) & 0xFF)
	libStr[1] = byte(n & 0xFF)

	H.Reset()
	_, _ = H.Write(zPad)
	_, _ = H.Write(msg)
	_, _ = H.Write(libStr)
	_, _ = H.Write([]byte{0})
	_, _ = H.Write(e.dst)
	b0 := H.Sum(nil)

	H.Reset()
	_, _ = H.Write(b0)
	_, _ = H.Write([]byte{1})
	_, _ = H.Write(e.dst)
	bi := H.Sum(nil)
	pseudo := append([]byte{}, bi...)
	for i := uint(2); i <= ell; i++ {
		H.Reset()
		_, _ = H.Write(xor(bi, b0))
		_, _ = H.Write([]byte{byte(i)})
		_, _ = H.Write(e.dst)
		bi = H.Sum(nil)
		pseudo = append(pseudo, bi...)
	}
	return pseudo[0:n]
}

// fieldEncoding은 HashToScalar를 구현
type fieldEncoding struct {
	F   GF.Field // 필드 객체
	Exp Expander // Expander 인터페이스는 정의
	L   uint     // 출력 길이
}

func (f *fieldEncoding) GetScalarField() GF.Field {
	return f.F
}

/*
	func (f *fieldEncoding) Hash(msg []byte) GF.Elt {
		pseudo := f.Exp.Expand(msg, f.L)
		return f.F.Elt(pseudo) // Elt 메서드는 필드 원소를 생성
	}
*/
func (f *fieldEncoding) Hash(msg []byte) GF.Elt { return f.hashToField(msg, 1)[0] }

// hashToField is a function that hashes a string msg of any length into an
// element of a finite field.
func (f *fieldEncoding) hashToField(
	msg []byte, // msg is the message to hash.
	count uint, // count is 1 or 2 (the length of the result array).
) []GF.Elt {
	m := f.F.Ext()
	length := count * m * f.L

	pseudo := f.Exp.Expand(msg, length)
	u := make([]GF.Elt, count)
	v := make([]interface{}, m)
	p := f.F.P()
	for i := uint(0); i < count; i++ {
		for j := uint(0); j < m; j++ {
			offset := f.L * (j + i*m)
			t := pseudo[offset : offset+f.L]
			vj := new(big.Int).SetBytes(t)
			v[j] = vj.Mod(vj, p)
		}
		u[i] = f.F.Elt(v)
	}
	return u
}

// sqrtRatio 함수는 제곱근 여부와 결과를 계산
func (m *sswu) sqrtRatio(u GF.Elt, v GF.Elt) (bool, GF.Elt) {
	F := m.E.F
	r := F.Inv(v)
	r = F.Mul(r, u)
	if F.IsSquare(r) {
		return true, F.Sqrt(r)
	}
	r = F.Mul(r, m.Z)
	return false, F.Sqrt(r)
}

type sswu struct {
	E      C.W
	Z      GF.Elt
	c1, c2 GF.Elt
}

func (m *sswu) verify() bool {
	F := m.E.F
	precond1 := !F.IsZero(m.E.A)         // A != 0
	precond2 := !F.IsZero(m.E.B)         // B != 0
	cond1 := !F.IsSquare(m.Z)            // Z is non-square
	cond2 := !F.AreEqual(m.Z, F.Elt(-1)) // Z != -1
	t0 := F.Mul(m.Z, m.E.A)              // Z*A
	t0 = F.Inv(t0)                       // 1/(Z*A)
	t0 = F.Mul(t0, m.E.B)                // B/(Z*A)
	g := m.E.EvalRHS(t0)                 // g(B/(Z*A))
	cond4 := F.IsSquare(g)               // g(B/(Z*A)) is square
	return precond1 && precond2 && cond1 && cond2 && cond4
}

func (m *sswu) precmp() {
	F := m.E.F

	t0 := F.Inv(m.E.A)    // 1/A
	t0 = F.Mul(t0, m.E.B) // B/A
	m.c1 = F.Neg(t0)      // -B/A
	t0 = F.Inv(m.Z)       // 1/Z
	m.c2 = F.Neg(t0)      // -1/Z
}

func newSSWU(e C.EllCurve, z GF.Elt) MapToCurve {
	curve := e.(C.W)
	if s := (&sswu{E: curve, Z: z}); s.verify() {
		s.precmp()
		return s
	}
	panic(fmt.Errorf("Failed restrictions for sswu"))
}

func NewSSWU(e C.EllCurve, z GF.Elt, iso func() C.Isogeny) MapToCurve {
	E := e.(C.W)
	F := E.F
	cond1 := F.IsZero(E.A)
	cond2 := F.IsZero(E.B)
	cond3 := iso != nil
	if (cond1 || cond2) && cond3 {
		isogeny := iso()
		return &sswuAB0{E, isogeny, newSSWU(isogeny.Domain(), z)}
	}
	return newSSWU(e, z)
}

// Map 메서드는 SSWU 매핑을 사용하여 필드 원소를 타원 곡선 상의 점으로 매핑
func (m *sswu) Map(u GF.Elt) C.Point {
	// 제공된 SSWU 매핑 로직 구현
	F := m.E.F
	var tv1, tv2, tv3, tv4, tv5, tv6, x, y GF.Elt
	tv1 = F.Sqr(u)                                //    1.  tv1 = u^2
	tv1 = F.Mul(m.Z, tv1)                         //    2.  tv1 = Z * tv1
	tv2 = F.Sqr(tv1)                              //    3.  tv2 = tv1^2
	tv2 = F.Add(tv2, tv1)                         //    4.  tv2 = tv2 + tv1
	tv3 = F.Add(tv2, F.One())                     //    5.  tv3 = tv2 + 1
	tv3 = F.Mul(m.E.B, tv3)                       //    6.  tv3 = B * tv3
	tv4 = F.CMov(m.Z, F.Neg(tv2), !F.IsZero(tv2)) //    7.  tv4 = CMOV(Z, -tv2, tv2 != 0)
	tv4 = F.Mul(m.E.A, tv4)                       //    8.  tv4 = A * tv4
	tv2 = F.Sqr(tv3)                              //    9.  tv2 = tv3^2
	tv6 = F.Sqr(tv4)                              //    10. tv6 = tv4^2
	tv5 = F.Mul(m.E.A, tv6)                       //    11. tv5 = A * tv6
	tv2 = F.Add(tv2, tv5)                         //    12. tv2 = tv2 + tv5
	tv2 = F.Mul(tv2, tv3)                         //    13. tv2 = tv2 * tv3
	tv6 = F.Mul(tv6, tv4)                         //    14. tv6 = tv6 * tv4
	tv5 = F.Mul(m.E.B, tv6)                       //    15. tv5 = B * tv6
	tv2 = F.Add(tv2, tv5)                         //    16. tv2 = tv2 + tv5
	x = F.Mul(tv1, tv3)                           //    17.   x = tv1 * tv3
	isGx1Square, y1 := m.sqrtRatio(tv2, tv6)      //    18. (is_gx1_square, y1) = sqrt_ratio(tv2, tv6)
	y = F.Mul(tv1, u)                             //    19.   y = tv1 * u
	y = F.Mul(y, y1)                              //    20.   y = y * y1
	x = F.CMov(x, tv3, isGx1Square)               //    21.   x = CMOV(x, tv3, is_gx1_square)
	y = F.CMov(y, y1, isGx1Square)                //    22.   y = CMOV(y, y1, is_gx1_square)
	e1 := F.Sgn0(u) == F.Sgn0(y)                  //    23.  e1 = sgn0(u) == sgn0(y)
	y = F.CMov(F.Neg(y), y, e1)                   //    24.   y = CMOV(-y, y, e1)
	tv4 = F.Inv(tv4)                              //    25.   x = x / tv4
	x = F.Mul(x, tv4)
	return m.E.NewPoint(x, y) // 타원 곡선 상의 새로운 점 생성
}

type encoding struct {
	F   GF.Field
	Exp Expander
	L   uint
}

type sswuAB0 struct {
	E   C.W
	iso C.Isogeny
	MapToCurve
}

func (m sswuAB0) String() string { return fmt.Sprintf("Simple SWU AB==0 for E: %v", m.E) }

func (m *sswuAB0) Map(u GF.Elt) C.Point { return m.iso.Push(m.MapToCurve.Map(u)) }

// encodeToCurve
type encodeToCurve struct {
	*encoding       // encoding 구조체 정의
	Map       *sswu // SSWU 매핑 인스턴스
	E         C.EllCurve
	Field     *fieldEncoding
}

func (e *encoding) GetHashToScalar() HashToScalar {
	return &fieldEncoding{
		F:   e.F,
		Exp: e.Exp, // Expander 인터페이스 구현
		L:   e.L,
	}
}

/*
func (s *encodeToCurve) Hash(in []byte) C.Point {
	// 입력 문자열을 필드 원소로 변환
	u := s.GetHashToScalar().Hash(in)

	// 필드 원소를 타원 곡선 상의 점으로 매핑
	Q := s.Map.Map(u)

	// 코팩터 클리어링을 통해 최종 타원 곡선 점을 얻음
	P := s.E.ClearCofactor(Q)
	return P
}
*/

// hashToCurve의 예제 구현
type hashToCurve struct {
	*encoding       // encoding 구조체는 정의
	Map       *sswu // SSWU 매핑 인스턴스
	E         C.EllCurve
	Field     *fieldEncoding
	Isogeny   C.Isogeny
}

func (s *encodeToCurve) IsRandomOracle() bool { return false }
func (s *encodeToCurve) Hash(in []byte) C.Point {
	u := s.Field.hashToField(in, 1)
	Q := s.Map.Map(u[0])
	P := s.E.ClearCofactor(Q)
	return P
}

func (s *hashToCurve) IsRandomOracle() bool { return true }
func (s *hashToCurve) Hash(in []byte) C.Point {
	u := s.Field.hashToField(in, 2)
	Q0 := s.Map.Map(u[0])
	Q1 := s.Map.Map(u[1])
	R := s.E.Add(Q0, Q1)
	P := s.E.ClearCofactor(R)
	return P
}

//Isogeny transfer 필요 (P-> P'으로)
func (s *hashToCurve) IsogenyTransfer(P C.Point) C.Point {
	PPrime := s.Isogeny.Push(P)
	return PPrime
}
