#include "trama.h"

using namespace std;

/*
Arreglo de bytes(orden)
0 - 5 Direccion Origen
6 - 12 Direccion Destino
13 Tipo de protocolo
14 Version de protocolo y tamaño de cabecera
15 Tipo de servicio
16 - 17 Longitud total
18 - 19 Identificador
20 Flags (3 bits)
20 - 21 Posicion de Fragmento de la trama (13 bits)
22 - Tiempo de vida
23 - Protocolo
*/

Trama::Trama(){
    auxI1 = 0;
}
Trama::Trama(const Trama &t){ }
Trama& Trama::operator=(const Trama &t){ }

void Trama::setArrBytes(unsigned char byte, int contadorByte){

    bytes[contadorByte] = byte;

}

void Trama::ethernet(){

    imprimirEthernet(0, 5, "Direccion de origen: ");
    imprimirEthernet(6, 11, "Direccion de destino: ");
    imprimirEthernet(12, 13, "Tipo: ");

}

//Funcion para imprimir en hexadecimal
void Trama::imprimirEthernet(int minimo, int maximo,string campo){
    int i;
    cout<<campo ;

    for(i = minimo; i<= maximo; i++){
        if(i<11)
            printf("%02X:", bytes[i] & 0xFF);
        else
            printf("%02X ", bytes[i] & 0xFF);
    }

    if(i == 14)
        tipoDeCodigoEthernet();


    cout<<endl;
}

void Trama::tipoDeCodigoEthernet(){

    auxI1 += bytes[12] + bytes[13];

        switch(auxI1){
            case 8:
                printf("-> IPv4 ");
                break;
            case 14:
                printf("-> ARP ");
                break;
            case 181:
                printf("-> RARP ");
                break;
            case 355:
                printf("-> IPv6 ");

    }
}

void Trama::ipv4(){
    version_tamanio();
    tipodeServio();

    auxI1 = 0;
    auxS1 = c.convert(bytes[16],0,7);
    auxS2 = c.convert(bytes[17],0,7);
    auxI1 += c.binario_decimal(auxS1);
    auxI1 += c.binario_decimal(auxS2);
    cout<<"Longitud total: "<<auxI1<<" bytes" << endl;
    cout << "Identificador: " << identificador() << endl;
    flags();
    cout << "Posicion del fragmento: " << posicionFragmento() << endl;
    cout << "Tiempo de vida: " << tiempoVida() << endl;
    protocolo();

}

void Trama::version_tamanio(){

    auxS1 = c.convert(bytes[14], 4,7);
    auxS2 = c.convert(bytes[14], 0,3);

    if(auxS1 == "0100")
        cout<<"Version: IPv4"<<endl;
    else
        cout<<"Version: IPv6"<<endl;

    auxI1 = c.binario_decimal(auxS2);

    cout<<"Tamanio de cabecera: "<<auxI1*4<<" bytes"<<endl;
}

void Trama::tipodeServio(){
    auxS2 = c.convert(bytes[15],0,2);
    auxI1 = c.binario_decimal(auxS2);

    cout << "Tipo de servicio" << endl;
    cout << "Prioridad: " << auxI1 << " ";

    switch(auxI1){
        case 0:
            cout << "    " << "De rutina";
            break;
        case 1:
            cout << "    "  << "Prioritario";
            break;
        case 2:
            cout << "    "  << "Inmediato";
            break;
        case 3:
            cout << "    "  << "Relampago";
            break;
        case 4:
            cout << "    "  << "Invalidacion relampago";
            break;
        case 5:
            cout << "    "  << "Procesando llamada critica";
            break;
        case 6:
            cout << "    "  << "Control de trabajo de Internet";
            break;
        case 7:
            cout << "    "  << "Control de red";
    }

    cout << endl;
    auxS1 = c.convert(bytes[14],3,5);

    auxI1 = auxS1[0] - '0';
    auxS2 = (auxI1 == 0) ? "normal" : "bajo";
    cout  << "    " << "Retardo: " << auxS2 << endl;

    auxI1 = auxS1[1] - '0';
    auxS2 = (auxI1 == 0) ? "normal" : "bajo";
    cout  << "    " << "Rendimiento: " << auxS2 << endl;

    auxI1 = auxS1[2] - '0';
    auxS2 = (auxI1 == 0) ? "normal" : "bajo";
    cout  << "    " << "Fiabilidad: " << auxS2 << endl;
}

int Trama::identificador(){
    auxS1 = c.convert(bytes[18], 0, 7);
    auxS2 = c.convert(bytes[19], 0, 7);
    auxI1 = c.binario_decimal(auxS1);
    auxI2 = c.binario_decimal(auxS2);
    int identificador = auxI1 + auxI2;
    return identificador;
}

int Trama::longitudTotal(){
    auxS1 = c.convert(bytes[16], 0, 7);
    auxS2 = c.convert(bytes[17], 0, 7);
    auxI1 = c.binario_decimal(auxS1);
    auxI2 = c.binario_decimal(auxS2);
    int longTotal = auxI1 + auxI2;
    return longTotal;
}

void Trama::flags(){
    cout << "Flags" << endl;
    auxS1 = c.convert(bytes[20], 0, 2);
    auxI1 = auxS1[1] - '0';
    cout << "    " << "Bit reservado: " << auxS1[0] - '0' << endl;
    if(auxI1 == 0){
        cout << "    " << "Paquete divisible: " << auxS1[1] - '0' << endl;
    } else {
        cout << "    " << "Paquete no divisible: " << auxS1[1] - '0' << endl;
    }
    auxI1 = auxS1[2] - '0';
    if(auxI1 == 0){
        cout << "    " << "Ultimo fragmento: " << auxS1[1] - '0' << endl;
    } else {
        cout << "    " << "Fragmento intermedio: " << auxS1[1] - '0' << endl;
    }
}

int Trama::posicionFragmento(){
    auxS1 = c.convert(bytes[20], 3, 7);
    auxS2 = c.convert(bytes[21], 0, 7);
    auxI1 = c.binario_decimal(auxS1) + c.binario_decimal(auxS2);
    return auxI1;
}

int Trama::tiempoVida(){
    auxS1 = c.convert(bytes[22], 0, 7);
    auxI1 = c.binario_decimal(auxS1);
    return auxI1;
}

void Trama::protocolo(){
    cout << "Protocolo" << endl << "    ";
    auxS1 = c.convert(bytes[23], 0, 7);
    auxI1 = c.binario_decimal(auxS1);
    switch(auxI1){
    case 1:
        cout << auxI1 << ". ICMP v4" << endl;
        break;
    case 6:
        cout << auxI1 << ". TCP" << endl;
        break;
    case 17:
        cout << auxI1 << ". UDP" << endl;
        break;
    case 58:
        cout << auxI1 << ". ICMP v6" << endl;
        break;
    case 118:
        cout << auxI1 << ". STP" << endl;
        break;
    case 121:
        cout << auxI1 << ". SMP" << endl;
        break;
    }
}
