#include <iostream>
#include "trama.h"

using namespace std;

int main()
{
    FILE *archivo = fopen("ethernet_ipv6_nd.bin", "rb");
    unsigned char dato;

    int ParteTrama = 0;
    Trama t;
    int i = 0;

    if (archivo == NULL)
        printf("Error\n");
        
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