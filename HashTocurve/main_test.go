package h2c

import (
	"math/big"
	"testing"

	GF "github.com/armfazh/tozan-ecc/field"
	C "github.com/hyunwoo4/hashToCurve/HashTocuvre/curve"
)

// TestHashToCurve 함수는 hashToCurve 구조체의 기능을 테스트합니다.
func TestHashToCurve(t *testing.T) {
	// 필요한 초기화 및 설정
	f := GF.NewFp("p256", "115792089210356248762697446949407573530086143415290314195533631308867097853951")                                                       // 예시 필드
	curve := C.Weierstrass.New("P256", f, f.Elt("-3"), f.Elt("0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b"), big.NewInt(1), big.NewInt(1)) // 예시 타원곡선

	bls12381G2Curve, ok := newBLS12381G2Curve().(*C.W)
	if !ok {
		t.Fatalf("타입 단언 실패: bls12381G2Curve는 *C.W 타입이 아닙니다.")
	}

	// hasher 인스턴스 생성 및 사용
	hasher := &hashToCurve{
		Field: &fieldEncoding{
			F: bls12381G2Curve.Field(), // BLS12381G2 곡선의 필드
			// ... 나머지 초기화 코드 ...
		},
		Map: &sswu{
			E: bls12381G2Curve,
			Z: bls12381G2Curve.Field().Elt(1),
		},
		E: bls12381G2Curve,
	}

	testMsg := []byte("테스트 메시지")
	expectedPoint := curve.NewPoint(f.Elt("x 좌표"), f.Elt("y 좌표")) // 예상되는 타원 곡선 점

	// hashToCurve 메서드 호출
	resultPoint := hasher.Hash(testMsg)

	// 결과 검증
	if !resultPoint.IsEqual(expectedPoint) {
		t.Errorf("Hash 결과가 예상과 다릅니다. 받은 결과: %v, 예상 결과: %v", resultPoint, expectedPoint)
	}

	// 추가적인 검증 로직
}
