#ifndef TRAMA_H_INCLUDED
#define TRAMA_H_INCLUDED
#define TAM 81

#include <iostream>
#include <string>
#include "conversiones.h"


class Trama{
    private:
        int auxI1,auxI2;
        std::string auxS1;
        std::string auxS2;
        unsigned char bytes[TAM];
        Conversiones c;

    public:
        //Metodos basicos de una clase
        Trama();
        Trama(const Trama&);
        Trama& operator = (const Trama&);

        void setArrBytes(unsigned char,int);

        //Metodos para la trama Ethernet
        void ethernet();
        void imprimirEthernet(int, int, std::string);
        void tipoDeCodigoEthernet();


        //Metodos para el encabezado IPv4
        void ipv4();
        void version_tamanio();
        void tipodeServio();

        int longitudTotal();
        int identificador();
        void flags();
        int posicionFragmento();
        int tiempoVida();
        void protocolo();
        void checksum(int, std::string);
        void IPorigen();
        void IPdestino();
        void opcionesIP();

        //Metodos para el protocolo ICMPv4
        void ICMPv4();
        void tipoMensajeInformativoICMPv4();
        void codigoErrorICMPv4();

        void imprimirResto();

};


#endif // TRAMA_H_INCLUDED
