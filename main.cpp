#include <iostream>
#include "trama.h"

using namespace std;

int main()
{
    FILE *archivo = fopen("ethernet_ipv4_icmp_host_unreachable.bin", "rb");
    unsigned char dato;

    int ParteTrama = 0;
    Trama t;
    int i = 0;

    if (archivo == NULL)
        printf("Eror\n");
    else
    {
        while(!feof(archivo))
        {
            dato = getc(archivo);
            t.setArrBytes(dato, i);
            i++;
        }
        t.ethernet();
        t.imprimirResto();
    }

    return 0;
}
