pragma circom 2.0.0;

include "../../circuits/sha512/sha512.circom";
include "../../node_modules/circomlib/circuits/binsum.circom";

component main = Sha512(1024);
