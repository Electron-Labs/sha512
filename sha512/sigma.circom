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

include "xor3.circom";
include "rotate.circom";
include "shift.circom";

template SmallSigma(ra, rb, rc) {//32 to 64
    signal input in[64];
    signal output out[64];
    var k;

    component rota = RotR(64, ra);//32 to 64
    component rotb = RotR(64, rb);//32 to 64
    component shrc = ShR(64, rc);//32 to 64

    for (k=0; k<64; k++) {//32 to 64
        rota.in[k] <== in[k];
        rotb.in[k] <== in[k];
        shrc.in[k] <== in[k];
    }

    component xor3 = Xor3(64);//32 to 64
    for (k=0; k<64; k++) {//32 to 64
        xor3.a[k] <== rota.out[k];
        xor3.b[k] <== rotb.out[k];
        xor3.c[k] <== shrc.out[k];
    }

    for (k=0; k<64; k++) {//32 to 64
        out[k] <== xor3.out[k];
    }
}

template BigSigma(ra, rb, rc) {
    signal input in[64];//32 to 64
    signal output out[64];//32 to 64
    var k;

    component rota = RotR(64, ra);//32 to 64
    component rotb = RotR(64, rb);//32 to 64
    component rotc = RotR(64, rc);//32 to 64
    for (k=0; k<64; k++) {//32 to 64
        rota.in[k] <== in[k];
        rotb.in[k] <== in[k];
        rotc.in[k] <== in[k];
    }

    component xor3 = Xor3(64);//32 to 64

    for (k=0; k<64; k++) {//32 to 64
        xor3.a[k] <== rota.out[k];
        xor3.b[k] <== rotb.out[k];
        xor3.c[k] <== rotc.out[k];
    }

    for (k=0; k<64; k++) {//32 to 64
        out[k] <== xor3.out[k];
    }
}
