#ifndef TRAMA_H_INCLUDED
#define TRAMA_H_INCLUDED

#include <iostream>
#include <string>
#include <vector>
#include "conversiones.h"


class Trama{
    private:
        long auxI1,auxI2;
        std::string auxS1;
        std::string auxS2;
        std::vector<unsigned char> bytes;
        Conversiones c;

    public:
        //Metodos basicos de una clase
        Trama();
        Trama(const Trama&);
        Trama& operator = (const Trama&);

        void setArrBytes(unsigned char);

        //Estas funciones no deberian estar aqui pero pues ni pedo :(
        int btodecimal(int);
        int b2todecimal(int);

        //Metodos para la trama Ethernet
        void ethernet();
        void tipoDeCodigoEthernet();


        //Metodos para el encabezado IPv4
        void ipv4();
        void version_tamanio();
        void tipodeServicio();
        int identificador();
        void flags();
        int posicionFragmento();
        void protocolo(int);
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

        //Metodos para protocolo IPv6
        void IPv6();
        void clase_trafico();

        //Metodos para protocolo ICMPv6
        void ICMPv6();
        void tipoMensajeInformativoICMPv6();

        //Metodos para la cabecera TCP
        void TCP(int);

        //Metodos para la cabecera UDP
        void UDP(int);

        //Metodos para cabecera DNS
        void DNS(int, int);

        void limpiarTrama();

        void imprimirResto(int);
};


#endif // TRAMA_H_INCLUDED
