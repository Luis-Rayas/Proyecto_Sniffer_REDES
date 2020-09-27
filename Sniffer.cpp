#include <iostream>
#include <stdio.h>

using namespace std;

int icar = 0;
void imprimir(int, int, string, int, unsigned char);
void tipoDeCodigo(unsigned char, int);

int main()
{
    FILE *archivo;
    unsigned char car;
    int bytes = 1;

    if ((archivo = fopen("ethernet_3.bin", "rb")) == NULL)
       printf ("Error en la apertura. Es posible que el fichero no exista.\n");
    else
        while(!feof(archivo))
            {
                fread(&car, sizeof(unsigned char), 1, archivo);

                imprimir(1, 6, "Direccion de origen: ", bytes, car);
                imprimir(7, 12, "Direccion de destino: ", bytes, car);
                imprimir(13, 14, "Tipo: ", bytes, car);
                imprimir(15, 1517, "Datos: ",bytes, car);
                bytes++;
            }
    fclose (archivo);
    return (0);
}

void imprimir(int min, int max, string campo, int bytes, unsigned char car){

    if(bytes >= min && bytes <= max){
        if(bytes == min)
            cout<<campo;

        if(bytes<13)
            printf("%02X:", car & 0xFF);
        else
            printf("%02X ", car & 0xFF);

        if(bytes == 13 || bytes ==14)
            tipoDeCodigo(car, bytes);

        if(bytes == max)
            printf("\b \n");
    }
}

void tipoDeCodigo(unsigned char car, int bytes){
    icar += car;

    if(bytes == 14){

        if(icar == 14)
            printf("-> ARP ");

        if(icar == 181)
            printf("-> RARP ");

        if(icar == 8)
            printf("-> IPv4 ");

        if(icar == 355)
            printf("-> IPv6 ");
    }
}
