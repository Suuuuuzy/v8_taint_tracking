// Copyright 2021 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Helper functions that operate on {Digits} vectors of digits.

#ifndef V8_BIGINT_VECTOR_ARITHMETIC_H_
#define V8_BIGINT_VECTOR_ARITHMETIC_H_

#include "src/bigint/bigint.h"
#include "src/bigint/digit-arithmetic.h"

namespace v8 {
namespace bigint {

// Z += X.
void AddAt(RWDigits Z, Digits X);

// Z -= X.
void SubAt(RWDigits Z, Digits X);

// Z := X + Y.
void Add(RWDigits Z, Digits X, Digits Y);

// Z := X - Y.
void Subtract(RWDigits Z, Digits X, Digits Y);

// X += y.
inline void Add(RWDigits X, digit_t y) {
  digit_t carry = y;
  int i = 0;
  do {
    X[i] = digit_add2(X[i], carry, &carry);
    i++;
  } while (carry != 0);
}

// X -= y.
inline void Subtract(RWDigits X, digit_t y) {
  digit_t borrow = y;
  int i = 0;
  do {
    X[i] = digit_sub(X[i], borrow, &borrow);
    i++;
  } while (borrow != 0);
}

// These add exactly Y's digits to the matching digits in X, storing the
// result in (part of) Z, and return the carry/borrow.
digit_t AddAndReturnCarry(RWDigits Z, Digits X, Digits Y);
digit_t SubtractAndReturnBorrow(RWDigits Z, Digits X, Digits Y);

inline bool IsDigitNormalized(Digits X) { return X.len() == 0 || X.msd() != 0; }

inline bool GreaterThanOrEqual(Digits A, Digits B) {
  return Compare(A, B) >= 0;
}

}  // namespace bigint
}  // namespace v8

#endif  // V8_BIGINT_VECTOR_ARITHMETIC_H_
