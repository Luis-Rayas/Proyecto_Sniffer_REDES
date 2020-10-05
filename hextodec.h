#ifndef HEXTODEC_H_INCLUDED
#define HEXTODEC_H_INCLUDED

class HexToDec{
public:
    int hexadecimalToDecimal(char hexVal[]);
};

int HexToDec::hexadecimalToDecimal(char hexVal[])
{
    int len = strlen(hexVal);
    int base = 1;
    int dec_val = 0;

    for (int i=len-1; i>=0; i--)
    {

        if (hexVal[i]>='0' && hexVal[i]<='9')
        {
            dec_val += (hexVal[i] - 48)*base;
            base = base * 16;
        }

        else if (hexVal[i]>='A' && hexVal[i]<='F')
        {
            dec_val += (hexVal[i] - 55)*base;
            base = base*16;
        }
    }
    return dec_val;
}


#endif // HEXTODEC_H_INCLUDED
