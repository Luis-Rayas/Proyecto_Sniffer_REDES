#include "trama.h"

using namespace std;

/*
Arreglo de bytes(orden)
0 - 5 Direccion Origen
6 - 12 Direccion Destino
13 Tipo de protocolo
14 Version de protocolo y tama�o de cabecera
15 Tipo de servicio
16 - 17 Longitud total
18 - 19 Identificador
20 Flags (3 bits)
20 - 21 Posicion de Fragmento de la trama (13 bits)
22 - Tiempo de vida
23 - Protocolo
24 - 25 Checksum
26 - 29 IP origen
30 - 33 IP destino
34 Tipo de mensaje informativo ICMPv4
35 Codigo de Error
36 - 37 Checksum ICMPv4
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
                ipv4();
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
    cout<<"Longitud total: "<<longitudTotal()<<" bytes" << endl;
    cout << "Identificador: " << identificador() << endl;
    flags();
    cout << "Posicion del fragmento: " << posicionFragmento() << endl;
    cout << "Tiempo de vida: " << tiempoVida() << endl;
    protocolo();
    checksum(24, "IPv4");
    IPorigen();
    IPdestino();
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
    auxI1 = 0;
    auxS1 = bytes[16] + bytes[17];
    auxS2 = c.convert2(auxS1, 0, 15);
    auxI1 = c.binario_decimal(auxS2);
    return auxI1;
}

void Trama::flags(){
    auxS1 = c.convert(bytes[20], 5, 7);
    cout << "Flags " << "( " << auxS1 << " ) "<< endl;
    auxI1 = auxS1[1] - '0';
    cout << "    " << "Bit reservado: " << auxS1[0] - '0' << endl;
    if(auxI1 == 0){
        cout << "    " << "Paquete divisible: " << auxS1[1] - '0' << endl;
    } else {
        cout << "    " << "Paquete no divisible: " << auxS1[1] - '0' << endl;
    }
    auxI1 = auxS1[2] - '0';
    if(auxI1 == 0){
        cout << "    " << "Ultimo fragmento: " << auxS1[2] - '0' << endl;
    } else {
        cout << "    " << "Fragmento intermedio: " << auxS1[2] - '0' << endl;
    }
}

int Trama::posicionFragmento(){
    //auxS1 = c.convert(bytes[20], 4, 0);
    auxS1 = c.convert(bytes[20], 4, 0) + c.convert(bytes[21], 0, 7);;
    //auxS2 = c.convert(bytes[21], 0, 7);
    auxI1 = c.binario_decimal(auxS1);
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
        ICMPv4();
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

void Trama::checksum(int noByte, string tipoDeChecksum){
    auxS1 = c.convert(bytes[noByte], 0, 7) + c.convert(bytes[noByte + 1], 0 ,7);
    printf("Checksum de %s: %02X:%02X \n",tipoDeChecksum.c_str(), bytes[noByte] & 0xFF, bytes[noByte + 1] & 0xFF);
}

void Trama::IPorigen(){
    int direccionOrigen[4];
    auxS1 = c.convert(bytes[26], 0, 7);
    direccionOrigen[0] = c.binario_decimal(auxS1);

    auxS1 = c.convert(bytes[27], 0, 7);
    direccionOrigen[1] = c.binario_decimal(auxS1);

    auxS1 = c.convert(bytes[28], 0, 7);
    direccionOrigen[2] = c.binario_decimal(auxS1);

    auxS1 = c.convert(bytes[29], 0, 7);
    direccionOrigen[3] = c.binario_decimal(auxS1);

    cout << "Direccion Origen: " << direccionOrigen[0] << "." << direccionOrigen[1] << "." << direccionOrigen[2]<< "." << direccionOrigen[3] << endl;
}
void Trama::IPdestino(){
    int direccionDestino[4];
    auxS1 = c.convert(bytes[30], 0, 7);
    direccionDestino[0] = c.binario_decimal(auxS1);

    auxS1 = c.convert(bytes[31], 0, 7);
    direccionDestino[1] = c.binario_decimal(auxS1);

    auxS1 = c.convert(bytes[32], 0, 7);
    direccionDestino[2] = c.binario_decimal(auxS1);

    auxS1 = c.convert(bytes[33], 0, 7);
    direccionDestino[3] = c.binario_decimal(auxS1);

    cout << "Direccion Destino: " << direccionDestino[0] << "." << direccionDestino[1] << "." << direccionDestino[2]<< "." << direccionDestino[3] << endl;
}

void Trama::ICMPv4() 
{
    cout << "ICMPv4: " << endl;
    tipoMensajeInformativoICMPv4();
    codigoErrorICMPv4();
    checksum(36, "ICMPv4");
}

void Trama::tipoMensajeInformativoICMPv4() 
{
    auxS1 = c.convert(bytes[34], 0, 7);
    auxI1 = c.binario_decimal(auxS1);
    switch (auxI1)
    {
    case 0:
        cout << "Echo Reply (Respuesta de Eco)" << endl;
        break;
    case 3:
        cout << "Destination Unreacheable (destino inaccesible)" << endl;
        break;
    case 4:
        cout << "Source Quench (disminución del tráfico desde el origen)" << endl;
        break;
    case 5:
        cout << "Redirect (redireccionar - cambio de ruta)" << endl;
        break;
    case 8:
        cout << "Echo (Solicitud de eco)" << endl;
        break;
    case 11:
        cout << "Time Exeeded (Tiempo exedido para un datagrama" << endl;
        break;
    case 12:
        cout << "Parameter problem (Problema de parametro)" << endl;
        break;
    case 13:
        cout << "Timestamp (solicitud de marca de tiempo)" << endl;
        break;
    case 14:
        cout << "Timestamp Reply(respuesta de marca de tiempo)" << endl;
        break;
    case 15:
        cout << "Information Request(solicitud de información) - obsoleto - " << endl;
        break;
    case 16:
        cout << "Information Reply (respuesta de información) - obsoleto - " << endl;
        break;
    case 17:
        cout << "Addressmask(solicitud de máscara de dirección)" << endl;
        break;
    case 18:
        cout << "Addressmask Reply (respuesta de máscara de dirección" << endl;
        break;
    default:
        cout << "Codigo de mensaje de error ICMPv4 no reconocido..." << endl;
    }
}

void Trama::codigoErrorICMPv4() 
{
    auxS1 = c.convert(bytes[35], 0, 7);
    auxI1 = c.binario_decimal(auxS1);
    switch (auxI1)
    {
    case 0:
        cout << "No se puede llegar a la red" << endl;
        break;
    case 1:
        cout << "No se puede llegar al host o aplicacion destino" << endl;
        break;
    case 2:
        cout << "El destino no dispone del protocolo solicitado" << endl;
        break;
    case 3:
        cout << "No se puede llegar al puerto destino o la aplicacion destino no esta libre" << endl;
        break;
    case 4:
        cout << "Se necesita aplicar fragmentacion pero el flag correspondiente indica lo contrario" << endl;
        break;
    case 5:
        cout << "La ruta de origen no es correcta" << endl;
        break;
    case 6:
        cout << "No se conoce la red destino" << endl;
        break;
    case 7:
        cout << "No se conoce el host destino" << endl;
        break;
    case 8:
        cout << "El host origen esta aislado" << endl;
        break;
    case 9:
        cout << "La comunicacion con la red destino esta prohibida por razones administrativas" << endl;
        break;
    case 10:
        cout << "La comunicacion con el host destino esta prohibido por razones administrativas" << endl;
        break;
    case 11:
        cout << "No se puede llegar a la red destino debido al tipo de servicio" << endl;
        break;
    case 12:
        cout << "No se puede llegar al host destino debido al tipo de servicio" << endl;
        break;
    default:
        cout << "Codigo de error ICMPv4 no reconocido..." << endl;
    }
}



void Trama::imprimirResto(){
    cout << "Datos: ";
    for (int i = 38; i < sizeof(bytes); i++){
        printf("%02X  ", bytes[i] & 0xFF);
        if((i%10) == 0 )
            cout << endl;
    }
}
