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

        //
        std::string convert(char,int,int);
        std::string convert2(std::string,int,int);
        int binario_decimal(std::string);




};

#endif // CONVERSIONES_H_INCLUDED
