#ifndef CONVERSIONES_H_INCLUDED
#define CONVERSIONES_H_INCLUDED

#include <iostream>
#include <string>

class Conversiones{
    private:
        int auxI1;
        int auxI2;
        std::string auxS1;
        std::string auxS2;

    public:
        std::string convert(char,int,int);
        int stringbinario_decimal(std::string);
        //Estas funciones tambien pueden ir en trama si quiere que lleve
        //menos parametros xd
        void imprimir_hexadecimal(int, int, int, int,std::string, unsigned char[]);
        
};

#endif // CONVERSIONES_H_INCLUDED
