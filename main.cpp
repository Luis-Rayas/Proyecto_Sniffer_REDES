#include <iostream>
#include "trama.h"

using namespace std;

int main()
{
    FILE *archivo = fopen("ethernet_arp_reply.bin", "rb");
    unsigned char dato;

    int ParteTrama = 0;
    Trama t;
    int i;

    if (archivo == NULL)
        printf("Eror\n");
    else
    {
        for (i = 0; !feof(archivo); i++)
        {
            dato = getc(archivo);
            t.setArrBytes(dato, i);
        }
        t.ethernet();
        t.imprimirResto();
    }

    return 0;
}
