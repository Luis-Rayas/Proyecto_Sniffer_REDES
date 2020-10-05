#include <iostream>
#include <stdio.h>

#define TAM 81

using namespace std;

//Primera practica
void analisisEthernet(int bytesCont, unsigned char dato);
void imprimir(int, int, string, int, unsigned char);
void tipoDeCodigo(unsigned char, int);

//Segunda practica
void tipoServicio(unsigned char[], int);
void identificador(unsigned char[], int);

int main()
{
    FILE *archivo = fopen("ethernet_ipv4_icmp_ping.bin", "rb");//fopen("ethernet_3.bin", "rb");
    unsigned char dato;
    int bytesCont = 1;
    int i;
    unsigned char bits[TAM];

    /*if(archivo == NULL)
       printf ("Error en la apertura. Es posible que el fichero no exista.\n");
    else
        while(!feof(archivo)){
            fread(&dato, sizeof(unsigned char), 1, archivo);
            analisisEthernet(bytesCont, dato);
            bytesCont++;
        }
    fclose (archivo);*/

    if(archivo == NULL) printf("Error\n");
    else{
        for(i = 0; i < TAM; i++){
            bits[i] = getc(archivo);
        }
        for(i = 0; i < TAM; i++){
            if(i == 8) tipoServicio(bits, i);
            if(i == 16) identificador(bits, i);
        }
    }

    return (0);
}

void analisisEthernet(int bytesCont, unsigned char dato){
    imprimir(1, 6, "Direccion de origen: ", bytesCont, dato);
    imprimir(7, 12, "Direccion de destino: ", bytesCont, dato);
    imprimir(13, 14, "Tipo: ", bytesCont, dato);
    imprimir(15, 1517, "Datos: ",bytesCont, dato);
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
    int idato = 0;
    idato += dato;

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

void tipoServicio(unsigned char dato[], int cont){
    short potencia[3] = {4, 2, 1};
    int serv = 0;
    int c, i;
    string x;

    for(i = 0; i < 3; i++){
        c = dato[i + cont] - '0';
        serv += c * potencia[i];
    }

    cout << "Tipo de servicio" << endl;
    cout << "Prioridad: " << serv << " ";

    switch(serv){
        case 0:
            cout << "De rutina";
            break;
        case 1:
            cout << "Prioritario";
            break;
        case 2:
            cout << "Inmediato";
            break;
        case 3:
            cout << "Relampago";
            break;
        case 4:
            cout << "Invalidacion relampago";
            break;
        case 5:
            cout << "Procesando llamada critica";
            break;
        case 6:
            cout << "Control de trabajo de Internet";
            break;
        case 7:
            cout << "Control de red";
    }
    cout << endl;

    cont += 3;
    c = dato[cont] - '0';
    x = (c == 0) ? "normal" : "bajo";
    cout << "Retardo: " << x << endl;

    cont++;
    c = dato[cont] - '0';
    x = (c == 0) ? "normal" : "bajo";
    cout << "Rendimiento: " << x << endl;

    cont++;
    c = dato[cont] - '0';
    x = (c == 0) ? "normal" : "bajo";
    cout << "Fiabilidad: " << x << endl;

    cont += 2; //porque los ultimos dos bits no se usan
}

void identificador(unsigned char dato[], int cont){
    cout << "Identificador: ";
    int limite = cont + 16;
    while(cont < limite){
        printf("%02X ", dato[cont] & 0xFF);
        cont++;
    }
}

void BtoD(string numero, int tam)
{
    int potencia[13] = {4096, 2048, 1024, 512, 256, 128, 64, 32, 16, 8, 4, 2, 1}, i, x, decimal[tam], total = 0;
    char temp[2];
    for (i = 0; numero[i] != '\0'; i++)
        ;
    int limite = i;
    i--;
    for (x = 0; x < limite; x++, i--)
    {
        temp[0] = numero[i];
        decimal[x] = atoi(temp);
        decimal[x] *= potencia[x];
        total += decimal[x];
    }
    printf("%d", total);
}