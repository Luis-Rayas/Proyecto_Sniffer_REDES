#include <iostream>
#include <stdio.h>

using namespace std;

void imprimir(int, int, string, int, unsigned char);
void tipoDeCodigo(unsigned char, int);

int main()
{
    FILE *archivo = fopen("ethernet_3.bin", "rb");
    unsigned char dato;
    int bytesCont = 1;

    if(archivo == NULL)
       printf ("Error en la apertura. Es posible que el fichero no exista.\n");
    else
        while(!feof(archivo)){
            fread(&dato, sizeof(unsigned char), 1, archivo);

            imprimir(1, 6, "Direccion de origen: ", bytesCont, dato);
            imprimir(7, 12, "Direccion de destino: ", bytesCont, dato);
            imprimir(13, 14, "Tipo: ", bytesCont, dato);
            imprimir(15, 1517, "Datos: ",bytesCont, dato);
            bytesCont++;
        }
    fclose (archivo);
    return (0);
}

void imprimir(int min, int max, string campo, int bytesCont, unsigned char dato){

    if(bytesCont >= min && bytesCont <= max){
        if(bytesCont == min)
            cout << campo;

        printf("%02X ", dato & 0xFF);

        if(bytesCont == 13 || bytesCont ==14)
            tipoDeCodigo(dato, bytesCont);

        if(bytesCont == max)
            printf("\b \n");
    }
}

void tipoDeCodigo(unsigned char dato, int bytesCont){
    int idato += dato;

    switch(bytesCont){
        case 8:
            printf("-> IPv4 ");
            break;
        case 14:
            printf("-> ARP ");
            break;
        case 181:
            printf("-> RARP ");
            break;
        case 255:
            printf("-> IPv6 ");

    }
}
