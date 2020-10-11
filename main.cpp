#include <iostream>
#include "trama.h"
#define TAM 81

using namespace std;

int main()
{
    FILE *archivo = fopen("PaquetesRedes/ethernet_ipv4_icmp_ping.bin", "rb");
    unsigned char dato;

    int ParteTrama = 0;
    Trama t;
    int i;

    if (archivo == NULL)
        printf("Error\n");
    else
    {
        for (i = 0; i < TAM; i++)
        {

            dato = getc(archivo);
            t.setArrBytes(dato, i);
        }
    }
    t.ethernet();
    t.imprimirResto();

    return 0;
}
