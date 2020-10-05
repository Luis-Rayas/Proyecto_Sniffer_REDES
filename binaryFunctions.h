#ifndef BINARYFUNCTIONS_H_INCLUDED
#define BINARYFUNCTIONS_H_INCLUDED

class BinaryFunction {
    public:
        void convertToBinary(const int);
        int binaryComplement(const int);
    };

void BinaryFunction::convertToBinary(const int b) {
    int binaryArray[8];
    int currentNumber = b;

    if(currentNumber >= 128) {
        currentNumber = currentNumber - 128;
        binaryArray[7] = 1;
        }
    if(currentNumber >= 64) {
        currentNumber = currentNumber - 64;
        binaryArray[6] = 1;
        }
    if(currentNumber >= 32) {
        currentNumber = currentNumber - 32;
        binaryArray[5] = 1;
        }
    if(currentNumber >= 16) {
        currentNumber = currentNumber - 16;
        binaryArray[4] = 1;
        }
    if(currentNumber >= 8) {
        currentNumber = currentNumber - 8;
        binaryArray[3] = 1;
        }
    if(currentNumber >= 4) {
        currentNumber = currentNumber - 4;
        binaryArray[2] = 1;
        }
    if(currentNumber >= 2) {
        currentNumber = currentNumber - 2;
        binaryArray[1] = 1;
        }
    if(currentNumber >= 1) {
        currentNumber = currentNumber - 1;
        binaryArray[0] = 1;
        }

    }

int BinaryFunction::binaryComplement(const int b) {
    int binaryArray[16];
    int currentNumber = b;
    int total = 0;
    int carry = 0;

    for(int i=0; i<16; i++) {
        binaryArray[i] = 0;
        }

    if(currentNumber >= 524288) {
        currentNumber = currentNumber - 524288;
        carry = carry + 8;
        }
    if(currentNumber >= 262144) {
        currentNumber = currentNumber - 262144;
        carry = carry + 4;
        }
    if(currentNumber >= 131072) {
        currentNumber = currentNumber - 131072;
        carry = carry + 2;
        }
    if(currentNumber >= 65536) {
        currentNumber = currentNumber - 65536;
        carry = carry + 1;
        }



    if(currentNumber >= 32768) {
        currentNumber = currentNumber - 32768;
        binaryArray[15] = 1;
        }
    if(currentNumber >= 16384) {
        currentNumber = currentNumber - 16384;
        binaryArray[14] = 1;
        }
    if(currentNumber >= 8192) {
        currentNumber = currentNumber - 8192;
        binaryArray[13] = 1;
        }
    if(currentNumber >= 4096) {
        currentNumber = currentNumber - 4096;
        binaryArray[12] = 1;
        }
    if(currentNumber >= 2048) {
        currentNumber = currentNumber - 2048;
        binaryArray[11] = 1;
        }
    if(currentNumber >= 1024) {
        currentNumber = currentNumber - 1024;
        binaryArray[10] = 1;
        }
    if(currentNumber >= 512) {
        currentNumber = currentNumber - 512;
        binaryArray[9] = 1;
        }
    if(currentNumber >= 256) {
        currentNumber = currentNumber - 256;
        binaryArray[8] = 1;
        }

    if(currentNumber >= 128) {
        currentNumber = currentNumber - 128;
        binaryArray[7] = 1;
        }
    if(currentNumber >= 64) {
        currentNumber = currentNumber - 64;
        binaryArray[6] = 1;
        }
    if(currentNumber >= 32) {
        currentNumber = currentNumber - 32;
        binaryArray[5] = 1;
        }
    if(currentNumber >= 16) {
        currentNumber = currentNumber - 16;
        binaryArray[4] = 1;
        }
    if(currentNumber >= 8) {
        currentNumber = currentNumber - 8;
        binaryArray[3] = 1;
        }
    if(currentNumber >= 4) {
        currentNumber = currentNumber - 4;
        binaryArray[2] = 1;
        }
    if(currentNumber >= 2) {
        currentNumber = currentNumber - 2;
        binaryArray[1] = 1;
        }
    if(currentNumber >= 1) {
        currentNumber = currentNumber - 1;
        binaryArray[0] = 1;
        }

    if(carry == 0) {
        for(int i=0; i<16; i++) {
            if(binaryArray[i] == 0) {
                binaryArray[i] = 1;
                }
            else {
                binaryArray[i] = 0;
                }
            }
        }

    if(binaryArray[15] == 1) {
        total = total + 32768;
        }
    if(binaryArray[14] == 1) {
        total = total + 16384;
        }
    if(binaryArray[13] == 1) {
        total = total + 8192;
        }
    if(binaryArray[12] == 1) {
        total = total + 4096;
        }
    if(binaryArray[11] == 1) {
        total = total + 2048;
        }
    if(binaryArray[10] == 1) {
        total = total + 1024;
        }
    if(binaryArray[9] == 1) {
        total = total + 512;
        }
    if(binaryArray[8] == 1) {
        total = total + 256;
        }

    if(binaryArray[7] == 1) {
        total = total + 128;
        }

    if(binaryArray[6] == 1) {
        total = total + 64;
        }

    if(binaryArray[5] == 1) {
        total = total + 32;
        }

    if(binaryArray[4] == 1) {
        total = total + 16;
        }

    if(binaryArray[3] == 1) {
        total = total + 8;
        }

    if(binaryArray[2] == 1) {
        total = total + 4;
        }

    if(binaryArray[1] == 1) {
        total = total + 2;
        }

    if(binaryArray[0] == 1) {
        total = total + 1;
        }

    total = total + carry;

    return total;
    }

#endif // BINARYFUNCTIONS_H_INCLUDED
