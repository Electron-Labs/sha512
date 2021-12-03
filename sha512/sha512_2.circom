/*
    Copyright 2018 0KIMS association.

    This file is part of circom (Zero Knowledge Circuit Compiler).

    circom is a free software: you can redistribute it and/or modify it
    under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    circom is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
    or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public
    License for more details.

    You should have received a copy of the GNU General Public License
    along with circom. If not, see <https://www.gnu.org/licenses/>.
*/
pragma circom 2.0.0;

include "constants.circom";
include "sha512compression.circom";
include "bitify.circom";

template Sha512_2() {
    signal input a;
    signal input b;
    signal output out;

    var i;
    var k;

    component bits2num = Bits2Num(440);
    component num2bits[2];

    num2bits[0] = Num2Bits(440);
    num2bits[1] = Num2Bits(440);

    num2bits[0].in <== a;
    num2bits[1].in <== b;


    component sha512compression = Sha512compression() ;

    component ha0 = H(0);
    component hb0 = H(1);
    component hc0 = H(2);
    component hd0 = H(3);
    component he0 = H(4);
    component hf0 = H(5);
    component hg0 = H(6);
    component hh0 = H(7);

    for (k=0; k<64; k++ ) {
        sha512compression.hin[0*64+k] <== ha0.out[k];
        sha512compression.hin[1*64+k] <== hb0.out[k];
        sha512compression.hin[2*64+k] <== hc0.out[k];
        sha512compression.hin[3*64+k] <== hd0.out[k];
        sha512compression.hin[4*64+k] <== he0.out[k];
        sha512compression.hin[5*64+k] <== hf0.out[k];
        sha512compression.hin[6*64+k] <== hg0.out[k];
        sha512compression.hin[7*64+k] <== hh0.out[k];
    }

    for (i=0; i<440; i++) {
        sha512compression.inp[i] <== num2bits[0].out[439-i];
        sha512compression.inp[i+440] <== num2bits[1].out[439-i];
    }

    sha512compression.inp[880] <== 1;

    for (i=881; i<1015; i++) {
        sha256compression.inp[i] <== 0;
    }

    sha512compression.inp[1015] <== 1;
    sha512compression.inp[1016] <== 1;
    sha512compression.inp[1017] <== 0;
    sha512compression.inp[1018] <== 1;
    sha512compression.inp[1019] <== 1;
    sha512compression.inp[1020] <== 0;
    sha512compression.inp[1021] <== 0;
    sha512compression.inp[1022] <== 0;
    sha512compression.inp[1023] <== 0;

    for (i=0; i<440; i++) {
        bits2num.in[i] <== sha512compression.out[511-i];
    }

    out <== bits2num.out;
}
