pragma circom 2.0.0;

include "../../circuits/sha512/sha512.circom";
include "../../circuits/binsum.circom";

component main = Sha512(1024);
