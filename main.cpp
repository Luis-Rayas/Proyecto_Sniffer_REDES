#include <iostream>
#include "trama.h"

using namespace std;

int main()
{
    FILE *archivo = fopen("ethernet_ipv4_tcp.bin", "rb");
    unsigned char dato;

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
    }
    return 0;
}