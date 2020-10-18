#include "trama.h"

using namespace std;

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
                ARP();
                break;
            case 181:
                printf("-> RARP ");
                RARP();
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
    IP_imprimir(26, "IP Origen: "); 
    IP_imprimir(30, "IP Destino: ");
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

void Trama::IP_imprimir(int x, string ip){
    int direccionOrigen[4];
    auxS1 = c.convert(bytes[x], 0, 7);
    direccionOrigen[0] = c.binario_decimal(auxS1);

    auxS1 = c.convert(bytes[x+1], 0, 7);
    direccionOrigen[1] = c.binario_decimal(auxS1);

    auxS1 = c.convert(bytes[x+2], 0, 7);
    direccionOrigen[2] = c.binario_decimal(auxS1);

    auxS1 = c.convert(bytes[x+3], 0, 7);
    direccionOrigen[3] = c.binario_decimal(auxS1);

    cout << ip << direccionOrigen[0] << "." << direccionOrigen[1] << "." << direccionOrigen[2]<< "." << direccionOrigen[3] << endl;
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

void Trama::ARP(){
    auxS1 = c.convert(bytes[14], 0, 7);
    auxS2 += auxS1;
    auxS1 = c.convert(bytes[15], 0, 7);
    auxS2 += auxS1;
    auxI1 = c.binario_decimal(auxS2);
    
    cout << "\nTipo de hardware: ";
    switch(auxI1){
        case 1:
            cout << "Ethernet (10mb)";
            break;
        case 6:
            cout << "IEEE 802 Networks";
            break;
        case 7:
            cout << "ARCNET";
            break;
        case 15:
            cout << "Frame Relay";
            break;
        case 16:
            cout << "Asynchronous Transfer Mode (ATM)";
            break;
        case 17:
            cout << "HDLC";
            break;
        case 18:
            cout << "Fibre Channel";
            break;
        case 19:
            cout << "Asynchronous Transfer Mode (ATM)";
            break;
        case 20:
            cout << "Serial Line";
    }
    cout << endl;
    printf("Tipo de protocolo: %02X%02X ", bytes[16] & 0xFF, bytes[17] & 0xFF);
    auxS2 = "";
    auxS1 = c.convert(bytes[16], 0, 7);
    auxS2 += auxS1;
    auxS1 = c.convert(bytes[17], 0, 7);
    auxS2 += auxS1;
    auxI1 = c.binario_decimal(auxS2);
    switch(auxI1){
        case 2048:
          cout << "--> IPv4";
          break;

        case 2054:
          cout << "--> ARP";
          break;

        case 32821:
          cout << "--> RARP";
          break;
        
        case 34525:
          cout << "--> IPv6";
          break;
    }
    cout << endl;
    cout << "Longitud de la dirección hardware en bytes: ";
    auxS1 = c.convert(bytes[18], 0, 7);
    cout << c.binario_decimal(auxS1) << endl;

    cout << "Longitud de la dirección protocolo en bytes: ";
    auxS1 = c.convert(bytes[19], 0, 7);
    cout << c.binario_decimal(auxS1) << endl;
    
    auxS2 = "";
    cout << "Codigo de operacion: ";
    auxS1 = c.convert(bytes[20], 0, 7);
    auxS2 += auxS1;
    auxS1 = c.convert(bytes[21], 0, 7);
    auxS2 += auxS1;
    auxI1 = c.binario_decimal(auxS2);

    switch(auxI1){
        case 1:
            cout << "ARP Request";
            break;
        case 2:
            cout << "ARP Reply";
            break;
        case 3:
            cout << "RARP Request";
            break;
        case 4:
            cout << "RARP Reply";
            break;
        case 5:
            cout << "DRARP Request";
            break;
        case 6:
            cout << "DRARP Reply";
            break;
        case 7:
            cout << "DRARP Error";
            break;
        case 8:
            cout << "InARP Request";
            break;
        case 9:
            cout << "InARP Reply";
    }
    cout << endl;
    
    printf("Direccion hardware emisor: %02X:%02X:", bytes[22] & 0xFF, bytes[23] & 0xFF);
    printf("%02X:%02X:", bytes[24] & 0xFF, bytes[25] & 0xFF);
    printf("%02X:%02X\n", bytes[26] & 0xFF, bytes[27] & 0xFF);

    IP_imprimir(28, "Direccion IP  del Emisor: ");

    printf("Direccion hardware receptor: %02X:%02X:", bytes[32] & 0xFF, bytes[33] & 0xFF);
    printf("%02X:%02X:", bytes[34] & 0xFF, bytes[35] & 0xFF);
    printf("%02X:%02X\n", bytes[36] & 0xFF, bytes[37] & 0xFF);

    IP_imprimir(38, "Direccion IP del receptor: ");

}

void Trama::RARP(){
    auxS1 = c.convert(bytes[14], 0, 7);
    auxS2 += auxS1;
    auxS1 = c.convert(bytes[15], 0, 7);
    auxS2 += auxS1;
    auxI1 = c.binario_decimal(auxS2);
    
    cout << "\nTipo de hardware: ";
    switch(auxI1){
        case 1:
            cout << "Ethernet (10mb)";
            break;
        case 6:
            cout << "IEEE 802 Networks";
            break;
        case 7:
            cout << "ARCNET";
            break;
        case 15:
            cout << "Frame Relay";
            break;
        case 16:
            cout << "Asynchronous Transfer Mode (ATM)";
            break;
        case 17:
            cout << "HDLC";
            break;
        case 18:
            cout << "Fibre Channel";
            break;
        case 19:
            cout << "Asynchronous Transfer Mode (ATM)";
            break;
        case 20:
            cout << "Serial Line";
    }
    cout << endl;
    printf("Tipo de protocolo: %02X%02X ", bytes[16] & 0xFF, bytes[17] & 0xFF);
    auxS2 = "";
    auxS1 = c.convert(bytes[16], 0, 7);
    auxS2 += auxS1;
    auxS1 = c.convert(bytes[17], 0, 7);
    auxS2 += auxS1;
    auxI1 = c.binario_decimal(auxS2);
    switch(auxI1){
        case 2048:
          cout << "--> IPv4";
          break;

        case 2054:
          cout << "--> ARP";
          break;

        case 32821:
          cout << "--> RARP";
          break;
        
        case 34525:
          cout << "--> IPv6";
          break;
    }
    cout << endl;
    cout << "Longitud de la dirección hardware en bytes: ";
    auxS1 = c.convert(bytes[18], 0, 7);
    cout << c.binario_decimal(auxS1) << endl;

    cout << "Longitud de la dirección protocolo en bytes: ";
    auxS1 = c.convert(bytes[19], 0, 7);
    cout << c.binario_decimal(auxS1) << endl;
    
    auxS2 = "";
    cout << "Codigo de operacion: ";
    auxS1 = c.convert(bytes[20], 0, 7);
    auxS2 += auxS1;
    auxS1 = c.convert(bytes[21], 0, 7);
    auxS2 += auxS1;
    auxI1 = c.binario_decimal(auxS2);

    switch(auxI1){
        case 1:
            cout << "ARP Request";
            break;
        case 2:
            cout << "ARP Reply";
            break;
        case 3:
            cout << "RARP Request";
            break;
        case 4:
            cout << "RARP Reply";
            break;
        case 5:
            cout << "DRARP Request";
            break;
        case 6:
            cout << "DRARP Reply";
            break;
        case 7:
            cout << "DRARP Error";
            break;
        case 8:
            cout << "InARP Request";
            break;
        case 9:
            cout << "InARP Reply";
    }
    cout << endl;
    
    printf("Direccion hardware emisor: %02X:%02X:", bytes[22] & 0xFF, bytes[23] & 0xFF);
    printf("%02X:%02X:", bytes[24] & 0xFF, bytes[25] & 0xFF);
    printf("%02X:%02X\n", bytes[26] & 0xFF, bytes[27] & 0xFF);

    IP_imprimir(28, "Direccion IP  del Emisor: ");

    printf("Direccion hardware receptor: %02X:%02X:", bytes[32] & 0xFF, bytes[33] & 0xFF);
    printf("%02X:%02X:", bytes[34] & 0xFF, bytes[35] & 0xFF);
    printf("%02X:%02X\n", bytes[36] & 0xFF, bytes[37] & 0xFF);

    IP_imprimir(38, "Direccion IP del receptor: ");

}

void Trama::imprimirResto(){
    cout << "Datos: ";
    for (int i = 38; i < sizeof(bytes); i++){
        printf("%02X  ", bytes[i] & 0xFF);
        if((i%10) == 0 )
            cout << endl;
    }
}
