package totp

import (
	"testing"
)

func TestMany(t *testing.T) {
	t.Run("For 30 seconds, TOTP must be the same", func(mt *testing.T) {
		input := []struct{ in int64
			expect string }{
			{
				in: 0, expect: "82276621",
			}, {
				in: 10,expect: "82276621",
			}, {
				in: 15,expect: "82276621",
			},
		}

		for _, a := range input {
			in := GenerateInput{AvailableForSeconds: 30, Digits: 8, Time: a.in}
			resp := GenerateTOTP(in)
			if resp != a.expect {
				mt.Errorf("For %d, I got %d...instead of %d", in.Time, resp, a.expect)
			}
		}
	})

}