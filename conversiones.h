#ifndef CONVERSIONES_H_INCLUDED
#define CONVERSIONES_H_INCLUDED

#include <iostream>
#include <vector>
#include <string>

class Conversiones{
    private:
        long auxI1;
        long auxI2;
        std::string auxS1;
        std::string auxS2;

    public:
        std::string convert(char,int,int);
        long stringbinario_decimal(std::string);
        void imprimir_hexadecimal(int, int, int, int,std::string, std::vector<unsigned char>);
        
};

#endif // CONVERSIONES_H_INCLUDED
