//CSE 4116 (Computer And Network Security Lab)
//Assignment on Hash function in cryptography
//Name: Rifat Arefin
//Roll: 1807117


#include<bits/stdc++.h>
using namespace std;

//Rotate to left function
uint32_t Rotate(uint32_t str, uint32_t times) {
    return  (str>>(32-times))|(str<<times) ;
}

//Storage for hash values
uint32_t A = 0x67452301;
uint32_t B = 0xEFCDAB89;
uint32_t C = 0x98BADCFE;
uint32_t D = 0x10325476;
uint32_t E = 0xC3D2E1F0;
   
//SHA function
void SHA_1(uint8_t *str, uint32_t s_len) {

    uint32_t len = ((((s_len + 8) / 64) + 1) * 64) - 8;
    uint8_t *msg = (uint8_t *)calloc(len + 64, 1);
    memcpy(msg, str, s_len);
    msg[s_len] = 0x80;
    uint32_t bits_len = s_len * 8;
    memcpy(msg+len, &bits_len, sizeof(uint32_t));

    for (uint32_t i = 0; i < len; i += 64) {
        uint32_t word[80];
        for (uint32_t j = 0; j < 16; j++) {
            word[j] = (msg[i+j*4] << 24) | (msg[i+j*4+1] << 16) | (msg[i+j*4+2] << 8) | (msg[i+j*4+3]);
        }
        for (uint32_t k = 16; k < 80; k++) {
            word[k] = Rotate((word[k-3]^word[k-8]^word[k-14]^word[k-16]), 1);
        }

        uint32_t a = A;
        uint32_t b = B;
        uint32_t c = C;
        uint32_t d = D;
        uint32_t e = E;

        for (uint32_t t=0; t<80; t++) {
            uint32_t fun, k;
            if (t <= 19) {
                fun = (b & c) | ((~b) & d);
                k = 0x5A827999;
            }
            else if (t <= 39) {
                fun = b^c^d;
                k = 0x6ED9EBA1;
            }
            else if (t <= 59) {
                fun = (b & c) | (b & d) | (c & d);
                k = 0x8F1BBCDC;
            }
            else {
                fun = b ^ c ^ d;
                k = 0xCA62C1D6;
            }

            uint32_t total = Rotate(a, 5) + fun + e + k + word[t];

            e = d;
            d = c;
            c = Rotate(b, 30);
            b = a;
            a = total;
        }

        A += a;
        B += b;
        C += c;
        D += d;
        E += e;
    }

    free(msg);
}


int main() {
    char *str = "Hello! Eid Mubarak.";  //Input String
    uint32_t s_len = strlen(str);   //String length


    //SHA-1 function call
    SHA_1((uint8_t *)str, s_len);


    //Print SHA Hash value for given input
    //cout<<""<<str<<endl;
    printf("Input string:  %s\n", str);
    printf("Hash value: %08x %08x %08x %08x %08x \n", A, B, C, D, E);
}
