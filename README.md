# SHA512

A circuit to compute SHA512 hash written in [Circom](https://github.com/iden3/circom).

## Installation
```
npm install
```

## Tests
```
npm test
```

## Usage

```circom
include "sha512/sha512/sha512.circom";
include "circomlib/binsum.circom"; // make sure to include binsum

var INPUT_BITS = 1024; // number of bits of the input message
component sha512 = Sha512(INPUT_BITS);
for (var i = 0; i < INPUT_BITS; i++) {
    sha512.in[i] <== nullifierBits[i];
}
for (var i = 0; i < 512; i++) {
    out[i] <== sha512.out[i];
}
```

## Constraint guarantees
The circuit only uses `<==` and doesn't use `<--` thus ensuring that the circuit correctly generates all the constraints.