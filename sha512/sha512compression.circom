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
include "t1.circom";
include "t2.circom";
include "binsum.circom";
include "sigmaplus.circom";
include "sha512compression_function.circom";


template Sha512compression() {// 256 to 512, 512 to 1024, 65 to 81,32 to 64 , 64 to 80
    signal input hin[512];
    signal input inp[1024];
    signal output out[512];
    signal a[81][64];
    signal b[81][64];
    signal c[81][64];
    signal d[81][64];
    signal e[81][64];
    signal f[81][64];
    signal g[81][64];
    signal h[81][64];
    signal w[80][64];


    var outCalc[512] = sha512compression(hin, inp);//256 to 512

    var i;
    for (i=0; i<512; i++) out[i] <-- outCalc[i];//256 to 512

    component sigmaPlus[64];//32 to 64
    for (i=0; i<64; i++) sigmaPlus[i] = SigmaPlus();

    component ct_k[80];//64 to 80
    for (i=0; i<80; i++) ct_k[i] = K(i);

    component t1[80];//64 to 80
    for (i=0; i<80; i++) t1[i] = T1();

    component t2[80];//64 to 80
    for (i=0; i<80; i++) t2[i] = T2();

    component suma[80];//64 to 80
    for (i=0; i<80; i++) suma[i] = BinSum(64, 2);//32 to 64

    component sume[80];//64 to 80
    for (i=0; i<80; i++) sume[i] = BinSum(64, 2);//32 to 64

    component fsum[8];
    for (i=0; i<8; i++) fsum[i] = BinSum(64, 2);//32 to 64

    var k;
    var t;

    for (t=0; t<80; t++) {//64 to 80
        if (t<16) {
            for (k=0; k<64; k++) {
                w[t][k] <== inp[t*64+63-k];//32 to 64, 31 to 63
            }
        } else {
            for (k=0; k<64; k++) {//32 to 64
                sigmaPlus[t-16].in2[k] <== w[t-2][k];
                sigmaPlus[t-16].in7[k] <== w[t-7][k];
                sigmaPlus[t-16].in15[k] <== w[t-15][k];
                sigmaPlus[t-16].in16[k] <== w[t-16][k];
            }

            for (k=0; k<64; k++) {//32 to 64
                w[t][k] <== sigmaPlus[t-16].out[k];
            }
        }
    }

    for (k=0; k<64; k++ ) {//32 to 64
        a[0][k] <== hin[k];
        b[0][k] <== hin[64*1 + k];//32 to 64
        c[0][k] <== hin[64*2 + k];//32 to 64
        d[0][k] <== hin[64*3 + k];//32 to 64
        e[0][k] <== hin[64*4 + k];//32 to 64
        f[0][k] <== hin[64*5 + k];//32 to 64
        g[0][k] <== hin[64*6 + k];//32 to 64
        h[0][k] <== hin[64*7 + k];//32 to 64
    }

    for (t = 0; t<80; t++) {//64 to 80
        for (k=0; k<64; k++) {//32 to 64
            t1[t].h[k] <== h[t][k];
            t1[t].e[k] <== e[t][k];
            t1[t].f[k] <== f[t][k];
            t1[t].g[k] <== g[t][k];
            t1[t].k[k] <== ct_k[t].out[k];
            t1[t].w[k] <== w[t][k];

            t2[t].a[k] <== a[t][k];
            t2[t].b[k] <== b[t][k];
            t2[t].c[k] <== c[t][k];
        }

        for (k=0; k<64; k++) {//32 to 64
            sume[t].in[0][k] <== d[t][k];
            sume[t].in[1][k] <== t1[t].out[k];

            suma[t].in[0][k] <== t1[t].out[k];
            suma[t].in[1][k] <== t2[t].out[k];
        }

        for (k=0; k<64; k++) {//32 to 64
            h[t+1][k] <== g[t][k];
            g[t+1][k] <== f[t][k];
            f[t+1][k] <== e[t][k];
            e[t+1][k] <== sume[t].out[k];
            d[t+1][k] <== c[t][k];
            c[t+1][k] <== b[t][k];
            b[t+1][k] <== a[t][k];
            a[t+1][k] <== suma[t].out[k];
        }
    }

    for (k=0; k<64; k++) {//32 to 64 and 64 to 80
        fsum[0].in[0][k] <==  hin[64*0+k];
        fsum[0].in[1][k] <==  a[80][k];
        fsum[1].in[0][k] <==  hin[64*1+k];
        fsum[1].in[1][k] <==  b[80][k];
        fsum[2].in[0][k] <==  hin[64*2+k];
        fsum[2].in[1][k] <==  c[80][k];
        fsum[3].in[0][k] <==  hin[64*3+k];
        fsum[3].in[1][k] <==  d[80][k];
        fsum[4].in[0][k] <==  hin[64*4+k];
        fsum[4].in[1][k] <==  e[80][k];
        fsum[5].in[0][k] <==  hin[64*5+k];
        fsum[5].in[1][k] <==  f[80][k];
        fsum[6].in[0][k] <==  hin[64*6+k];
        fsum[6].in[1][k] <==  g[80][k];
        fsum[7].in[0][k] <==  hin[64*7+k];
        fsum[7].in[1][k] <==  h[80][k];
    }

    for (k=0; k<64; k++) {//32 to 64 and multiple of 64...
        out[63-k]     === fsum[0].out[k];
        out[64+63-k]  === fsum[1].out[k];
        out[128+63-k]  === fsum[2].out[k];
        out[192+63-k]  === fsum[3].out[k];
        out[256+63-k] === fsum[4].out[k];
        out[320+63-k] === fsum[5].out[k];
        out[384+63-k] === fsum[6].out[k];
        out[448+63-k] === fsum[7].out[k];
    }
}
