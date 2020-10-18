#ifndef TRAMA_H_INCLUDED
#define TRAMA_H_INCLUDED

#include <iostream>
#include <string>
#include "conversiones.h"


class Trama{
    private:
        int auxI1,auxI2;
        std::string auxS1;
        std::string auxS2;
        unsigned char bytes[81];
        Conversiones c;

    public:
        //Metodos basicos de una clase
        Trama();
        Trama(const Trama&);
        Trama& operator = (const Trama&);

        void setArrBytes(unsigned char,int);

        //Estas funciones no deberian estar aqui pero pues ni pedo :(
        int btodecimal(int);
        int b2todecimal(int);
        
        //Metodos para la trama Ethernet
        void ethernet();
        void tipoDeCodigoEthernet();


        //Metodos para el encabezado IPv4
        void ipv4();
        void version_tamanio();
        void tipodeServio();
        int identificador();
        void flags();
        int posicionFragmento();
        void protocolo();
        void checksum(int, std::string);
        void IP_imprimir(int,std::string);
        void opcionesIP();

        //Metodos para el protocolo ICMPv4
        void ICMPv4();
        void tipoMensajeInformativoICMPv4();
        void codigoErrorICMPv4();

        //Metodos para el protocolo ARP/RARP
        void ARP();
        void RARP();

        void imprimirResto();


};


#endif // TRAMA_H_INCLUDED
