#include <iostream>

#include <winsock2.h>
#include <stdio.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <time.h>
#include <stdlib.h>

#include <string.h>
#include <fstream>

#include "pcap.h"
#include "ip.h"
#include "tcp.h"
#include "ethernet.h"
#include "hextodec.h"
#include "binaryFunctions.h"

#define LINE_LEN 16

using namespace std;

void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);

int main() {
    Ip ip;
    Tcp tcp;
    Ethernet ethernet;
    HexToDec hextodec;
    BinaryFunction binaryFunctions;

    int finish = 0;
    int option;
    int byte = 0;
    int byte2 = 0;
    int current = 0;
    int binaryFile[1000];
    int currentNumber = 0;
    int verifyServiceType[8];
    int verifyCurrentBits[8];
    int initialPosition;

    char packageName[30];
    char readHex[4];
    char fullFile[500];
    char convertHex[10];
    char protocol[6];
    char binaryBytes[8];

    while(finish == 0) {
        system("cls");
        cout << "SNIFFER - Paulo Celis" << endl << endl;
        cout << "1-Leer Paquete De Archivo" << endl;
        cout << "2-Mostrar Lista de Adaptadores" << endl;
        cout << "3-Identificar Adaptador Funcional" << endl;
        cout << "4-Buscar y Analizar Paquete de WiFi" << endl;
        cout << "5-Salir" << endl;
        cout << "Opcion: ";
        cin >> option;

        if(option == 1) {
            cout << "Nombre del paquete: ";
            cin >> packageName;
            strcat(packageName, ".txt");

            ifstream fileRead(packageName);

            if(!fileRead.good()) {
                cout << "No se pudo abrir el archivo" << endl;
                system("pause");
                }

            system("cls");
            cout << "INFORMACION DEL PAQUETE" << endl << endl;
            for(int i=0; i<500; i++) {
                fileRead.read((char*)&readHex,1);
                cout << readHex[0];
                if(readHex[0] != '\n') {
                    fullFile[current] = readHex[0];
                    current++;
                    }
                if(fileRead.eof()) {
                    break;
                    }
                }
            fullFile[current-1] = '\0';

            fileRead.close();


            for(int i=0; i<1000; i++) {
                binaryFile[i] = 0;
                }

            for(int i=0; i<1000; i=i+8) {
                readHex[0] = fullFile[currentNumber];
                readHex[1] = fullFile[currentNumber+1];
                readHex[2] = '\n';
                byte = hextodec.hexadecimalToDecimal(readHex);
                if(byte >= 128) {
                    binaryFile[i] = 1;
                    byte = byte - 128;
                    }
                if(byte >= 64) {
                    binaryFile[i+1] = 1;
                    byte = byte - 64;
                    }
                if(byte >= 32) {
                    binaryFile[i+2] = 1;
                    byte = byte - 32;
                    }
                if(byte >= 16) {
                    binaryFile[i+3] = 1;
                    byte = byte - 16;
                    }
                if(byte >= 8) {
                    binaryFile[i+4] = 1;
                    byte = byte - 8;
                    }
                if(byte >= 4) {
                    binaryFile[i+5] = 1;
                    byte = byte - 4;
                    }
                if(byte >= 2) {
                    binaryFile[i+6] = 1;
                    byte = byte - 2;
                    }
                if(byte >= 1) {
                    binaryFile[i+7] = 1;
                    byte = byte - 1;
                    }
                currentNumber = currentNumber + 2;
                }

            cout << endl << endl << "INFORMACION DEL PAQUETE EN BINARIO" << endl << endl;
            int j = 0;
            for(int i=0; i<1000; i++) {
                if(j >= 8) {
                    cout << ",";
                    j = 0;
                    }
                cout << binaryFile[i];
                j++;
                }


            cout << endl << endl;
            cout << "__________CABECERA ETHERNET__________" << endl << endl;

            cout << "Direccion MAC Origen: " << fullFile[0] << fullFile[1];
            cout << ":" << fullFile[2] << fullFile[3];
            cout << ":" << fullFile[4] << fullFile[5];
            cout << ":" << fullFile[6] << fullFile[7];
            cout << ":" << fullFile[8] << fullFile[9];
            cout << ":" << fullFile[10] << fullFile[11];
            cout << endl;

            cout << "Direccion MAC Destino: " << fullFile[12] << fullFile[13];
            cout << ":" << fullFile[14] << fullFile[15];
            cout << ":" << fullFile[16] << fullFile[17];
            cout << ":" << fullFile[18] << fullFile[19];
            cout << ":" << fullFile[20] << fullFile[21];
            cout << ":" << fullFile[22] << fullFile[23];
            cout << endl << endl;

            protocol[0] = fullFile[24];
            protocol[1] = fullFile[25];
            protocol[2] = fullFile[26];
            protocol[3] = fullFile[27];
            protocol[4] = '\0';

            cout << "------TABLA DE PROTOCOLOS------" << endl;
            cout << "      0800      |     IP_V4    " << endl;
            cout << "      86DD      |     IP_V6    " << endl;
            cout << "      0600      | XEROX NS IDP " << endl;
            cout << "      0801      | X.75 Internet" << endl;
            cout << "      0802      | NBS Internet " << endl;
            cout << "      0806      |      ARP     " << endl;
            cout << "      80F3      |      AARP    " << endl;
            cout << endl << endl;

            if(strcmp(protocol,"0800") == 0) {
                cout << "El protocolo encapsulado corresponde a IP_V4" << endl;
                cout << "Type: IP_V4 " << "Con el codigo: " << protocol << endl << endl;
                cout << "__________CABECERA IP__________" << endl << endl;
                }
            else if(strcmp(protocol,"86DD") == 0) {
                cout << "El protocolo encapsulado corresponde a IP_V6" << endl;
                cout << "Type: IP_V6" << endl << endl;
                cout << "Se esta desarrollando" << endl;
                system("pause");
                return 0;
                }
            else if(strcmp(protocol,"0600") == 0) {
                cout << "El protocolo encapsulado corresponde a XEROX NS IPD" << endl;
                cout << "Type: XEROX NS IDP" << endl << endl;
                cout << "Se esta desarrollando" << endl;
                system("pause");
                return 0;
                }
            else if(strcmp(protocol,"0801") == 0) {
                cout << "El protocolo encapsulado corresponde a X.75 Internet" << endl;
                cout << "Type: X.75 Internet" << endl << endl;
                cout << "Se esta desarrollando" << endl;
                system("pause");
                return 0;
                }
            else if(strcmp(protocol,"0802") == 0) {
                cout << "El protocolo encapsulado corresponde a NBS Internet" << endl;
                cout << "Type: NBS Internet" << endl << endl;
                cout << "Se esta desarrollando" << endl;
                system("pause");
                return 0;
                }
            else if(strcmp(protocol,"0806") == 0) {
                cout << "El protocolo encapsulado corresponde a ARP" << endl;
                cout << "Type: ARP" << endl << endl;
                cout << "Se esta desarrollando" << endl;
                system("pause");
                return 0;
                }
            else if(strcmp(protocol,"80F3") == 0) {
                cout << "El protocolo encapsulado corresponde a AARP" << endl;
                cout << "Type: AARP" << endl << endl;
                cout << "Se esta desarrollando" << endl;
                system("pause");
                return 0;
                }
            else {
                cout << "El protocolo encapsulado no esta definido" << endl;
                system("pause");
                }

            cout << "Version y Longitud: " << endl;

            convertHex[0] = fullFile[28];
            convertHex[1] = '\0';

            byte = atoi(convertHex);

            cout << "Version: " << convertHex[0] << endl;
            cout << "Longitud: " << convertHex[0];

            convertHex[0] = fullFile[29];
            convertHex[1] = '\0';

            byte2 = atoi(convertHex);

            cout << " * " << convertHex[0] << " = " << byte*byte2 << " BYTES" << endl << endl;

            cout << "Tipo de Servicio:    ";

            initialPosition = 120;
            for(int i=0; i<8; i++) {
                verifyServiceType[i] = binaryFile[initialPosition];
                initialPosition++;
                }

            for(int i=0; i<8; i++) {
                cout << verifyServiceType[i] << ".";
                }
            cout << endl;

            if(verifyServiceType[0] == 0 && verifyServiceType[1] == 0 &&
                    verifyServiceType[2] == 0) {
                cout << "Precedencia: Rutina" << endl;
                }
            else if(verifyServiceType[0] == 0 && verifyServiceType[1] == 0 &&
                    verifyServiceType[2] == 1) {
                cout << "Precedencia: Prioridad" << endl;
                }
            else {
                cout << "Precedencia: No definida" << endl;
                }

            if(verifyServiceType[3] == 0 && verifyServiceType[4] == 0 &&
                    verifyServiceType[5] == 0 && verifyServiceType[6] == 0) {
                cout << "Tipo de Servicio: Normal" << endl;
                }
            else if(verifyServiceType[3] == 1 && verifyServiceType[4] == 0 &&
                    verifyServiceType[5] == 0 && verifyServiceType[6] == 0) {
                cout << "Tipo de Servicio: Minimizar Retardo" << endl;
                }
            else {
                cout << "Tipo de Servicio: No definido" << endl;
                }

            if(verifyServiceType[7] == 0) {
                cout << "Must Be Zero: 0" << endl << endl;
                }
            else {
                cout << "Must Be Zero: 1" << endl << endl;
                }

            cout << "Longitud Total del Paquete: ";

            convertHex[0] = fullFile[32];
            convertHex[1] = fullFile[33];
            convertHex[2] = fullFile[34];
            convertHex[3] = fullFile[35];
            convertHex[4] = '\0';
            byte = hextodec.hexadecimalToDecimal(convertHex);

            cout << byte << " Bytes" << endl << endl;

            cout << "Identificacion: ";

            convertHex[0] = fullFile[36];
            convertHex[1] = fullFile[37];
            convertHex[2] = fullFile[38];
            convertHex[3] = fullFile[39];
            convertHex[4] = '\0';

            cout << "x" << convertHex << endl << endl;

            cout << "Banderas:      ";

            initialPosition = 160;
            for(int i=0; i<3; i++) {
                verifyCurrentBits[i] = binaryFile[initialPosition];
                initialPosition++;
                }

            for(int i=0; i<3; i++) {
                cout << verifyCurrentBits[i] << ".";
                }
            cout << endl;

            cout << "Reservado: " << verifyCurrentBits[0] << endl;
            cout << "Dont Fragment: " << verifyCurrentBits[1] << endl;
            cout << "More Fragments: " << verifyCurrentBits[2] << endl << endl;

            cout << "Desplazamiento: " << endl;

            if(binaryFile[162] == 0) {
                cout << "No hay desplazamiento" << endl << endl;
                }
            else {
                int totalDisplacement = 0;
                if(binaryFile[163] == 1) {
                    totalDisplacement = totalDisplacement + 4096;
                    }
                if(binaryFile[164] == 1) {
                    totalDisplacement = totalDisplacement + 2048;
                    }
                if(binaryFile[165] == 1) {
                    totalDisplacement = totalDisplacement + 1024;
                    }
                if(binaryFile[166] == 1) {
                    totalDisplacement = totalDisplacement + 512;
                    }
                if(binaryFile[167] == 1) {
                    totalDisplacement = totalDisplacement + 256;
                    }
                if(binaryFile[168] == 1) {
                    totalDisplacement = totalDisplacement + 128;
                    }
                if(binaryFile[169] == 1) {
                    totalDisplacement = totalDisplacement + 64;
                    }
                if(binaryFile[170] == 1) {
                    totalDisplacement = totalDisplacement + 32;
                    }
                if(binaryFile[171] == 1) {
                    totalDisplacement = totalDisplacement + 16;
                    }
                if(binaryFile[172] == 1) {
                    totalDisplacement = totalDisplacement + 8;
                    }
                if(binaryFile[173] == 1) {
                    totalDisplacement = totalDisplacement + 4;
                    }
                if(binaryFile[174] == 1) {
                    totalDisplacement = totalDisplacement + 2;
                    }
                if(binaryFile[175] == 1) {
                    totalDisplacement = totalDisplacement + 1;
                    }

                cout << totalDisplacement << "Bytes Para el Proximo Paquete" << endl << endl;
                }

            cout << "Tiempo de vida: ";

            convertHex[0] = fullFile[44];
            convertHex[1] = fullFile[45];
            convertHex[2] = '\0';
            byte = hextodec.hexadecimalToDecimal(convertHex);

            cout << byte << " segundos" << endl << endl;

            protocol[0] = fullFile[46];
            protocol[1] = fullFile[47];
            protocol[2] = '\0';
            byte = hextodec.hexadecimalToDecimal(convertHex);

            cout << "------TABLA DE PROTOCOLOS------" << endl;
            cout << "       01       |     ICMP    " << endl;
            cout << "       06       |     TCP    " << endl;
            cout << "       17       |     UDP    " << endl;

            cout << endl << endl;

            if(strcmp(protocol,"06") == 0) {
                cout << "El protocolo encapsulado corresponde a TCP" << endl;
                cout << "Protocolo: TCP, Con el codigo: 06, (Transmission Control)" << endl << endl;
                }
            else {
                cout << "El protocolo no esta definido" << endl;
                system("pause");
                }

            cout << "Checksum: ";

            convertHex[0] = fullFile[48];
            convertHex[1] = fullFile[49];
            convertHex[2] = fullFile[50];
            convertHex[3] = fullFile[51];
            convertHex[4] = '\0';
            byte = hextodec.hexadecimalToDecimal(convertHex);

            cout << byte << endl;

            cout << "Checksum Verificacion: " << endl;
            int checkSumIP = 0;
            int binaryComplementIP = 0;
            int currentPosition = 28;
            while(currentPosition < 68) {
                convertHex[0] = fullFile[currentPosition];
                convertHex[1] = fullFile[currentPosition+1];
                convertHex[2] = fullFile[currentPosition+2];
                convertHex[3] = fullFile[currentPosition+3];
                convertHex[4] = '\0';
                byte2 = hextodec.hexadecimalToDecimal(convertHex);
                if(currentPosition != 48) {
                    checkSumIP = checkSumIP + binaryFunctions.binaryComplement(byte2);
                    cout << convertHex << " : " << byte2 << " : " << binaryFunctions.binaryComplement(byte2) << endl;
                    }
                currentPosition = currentPosition + 4;
                }

            //cout << checkSumIP << " Complemento -> " << byte << endl << endl;
            cout << checkSumIP << " Complemento -> " << binaryFunctions.binaryComplement(checkSumIP) << endl << endl;

            cout << "Direccion IP Origen: ";

            convertHex[0] = fullFile[52];
            convertHex[1] = fullFile[53];
            convertHex[2] = '\0';
            byte = hextodec.hexadecimalToDecimal(convertHex);

            cout << byte << ".";

            convertHex[0] = fullFile[54];
            convertHex[1] = fullFile[55];
            convertHex[2] = '\0';
            byte = hextodec.hexadecimalToDecimal(convertHex);

            cout << byte << ".";

            convertHex[0] = fullFile[56];
            convertHex[1] = fullFile[57];
            convertHex[2] = '\0';
            byte = hextodec.hexadecimalToDecimal(convertHex);

            cout << byte << ".";

            convertHex[0] = fullFile[58];
            convertHex[1] = fullFile[59];
            convertHex[2] = '\0';
            byte = hextodec.hexadecimalToDecimal(convertHex);

            cout << byte << "." << endl << endl;

            cout << "Direccion IP Destino: ";

            convertHex[0] = fullFile[60];
            convertHex[1] = fullFile[61];
            convertHex[2] = '\0';
            byte = hextodec.hexadecimalToDecimal(convertHex);

            cout << byte << ".";

            convertHex[0] = fullFile[62];
            convertHex[1] = fullFile[63];
            convertHex[2] = '\0';
            byte = hextodec.hexadecimalToDecimal(convertHex);

            cout << byte << ".";

            convertHex[0] = fullFile[64];
            convertHex[1] = fullFile[65];
            convertHex[2] = '\0';
            byte = hextodec.hexadecimalToDecimal(convertHex);

            cout << byte << ".";

            convertHex[0] = fullFile[66];
            convertHex[1] = fullFile[67];
            convertHex[2] = '\0';
            byte = hextodec.hexadecimalToDecimal(convertHex);

            cout << byte << "." << endl << endl;



            cout << "__________CABECERA TCP__________" << endl << endl;

            cout << "Direccion de puerto origen: ";

            convertHex[0] = fullFile[68];
            convertHex[1] = fullFile[69];
            convertHex[2] = fullFile[70];
            convertHex[3] = fullFile[71];
            convertHex[4] = '\0';
            byte = hextodec.hexadecimalToDecimal(convertHex);

            cout << byte << endl << endl;

            cout << "Direccion de Puerto Destino: ";

            convertHex[0] = fullFile[72];
            convertHex[1] = fullFile[73];
            convertHex[2] = fullFile[74];
            convertHex[3] = fullFile[75];
            convertHex[4] = '\0';
            byte = hextodec.hexadecimalToDecimal(convertHex);

            cout << byte << endl << endl;

            cout << "Numero de Secuencia: ";

            convertHex[0] = fullFile[76];
            convertHex[1] = fullFile[77];
            convertHex[2] = fullFile[78];
            convertHex[3] = fullFile[79];
            convertHex[4] = fullFile[80];
            convertHex[5] = fullFile[81];
            convertHex[6] = fullFile[82];
            convertHex[7] = fullFile[83];
            convertHex[8] = '\0';
            byte = hextodec.hexadecimalToDecimal(convertHex);

            cout << byte << endl << endl;

            cout << "Numero de Confirmacion: ";

            convertHex[0] = fullFile[84];
            convertHex[1] = fullFile[85];
            convertHex[2] = fullFile[86];
            convertHex[3] = fullFile[87];
            convertHex[4] = fullFile[88];
            convertHex[5] = fullFile[89];
            convertHex[6] = fullFile[90];
            convertHex[7] = fullFile[91];
            convertHex[8] = '\0';
            byte = hextodec.hexadecimalToDecimal(convertHex);

            cout << byte << endl << endl;

            cout << "Longitud de la cabecera: ";

            int tcpSize = 0;
            if(binaryFile[368] == 1) {
                tcpSize = tcpSize + 8;
                }
            if(binaryFile[369] == 1) {
                tcpSize = tcpSize + 4;
                }
            if(binaryFile[370] == 1) {
                tcpSize = tcpSize + 2;
                }
            if(binaryFile[371] == 1) {
                tcpSize = tcpSize + 1;
                }

            cout << tcpSize << endl << endl;
            cout << tcpSize << " * 4 = " << tcpSize*4 << " BYTES" << endl << endl;

            cout << "Reservados: ";
            initialPosition = 372;
            for(int i=0; i<6; i++) {
                cout << binaryFile[initialPosition + i] << ".";
                }
            cout << endl << endl;

            cout << "Banderas: " ;
            initialPosition = 378;
            for(int i=0; i<6; i++) {
                cout << binaryFile[initialPosition + i] << ".";
                }
            cout << endl;

            cout << "Nonce: " << binaryFile[378] << endl;
            if(binaryFile[375] == 0) {
                cout << "Nonce No Es Significativo" << endl << endl;
                }
            else {
                cout << "Nonce Es Significativo" << endl << endl;
                }

            cout << "CWR: " << binaryFile[378] << endl;
            if(binaryFile[376] == 0) {
                cout << "Congestion Windows Reduced No Es Significativo" << endl << endl;
                }
            else {
                cout << "Congestion Windows Reduced Es Significativo" << endl << endl;
                }

            cout << "ECN-Echo: " << binaryFile[378] << endl;
            if(binaryFile[377] == 0) {
                cout << "ECN-Echo No Es Significativo" << endl << endl;
                }
            else {
                cout << "ECN-Echo Es Significativo" << endl << endl;
                }

            cout << "URG: " << binaryFile[378] << endl;
            if(binaryFile[378] == 0) {
                cout << "Urgent Pointer No Es Significativo" << endl << endl;
                }
            else {
                cout << "Urgent Pointer Es Significativo" << endl << endl;
                }

            cout << "ACK: " << binaryFile[379] << endl;
            if(binaryFile[379] == 0) {
                cout << "El Campo De Reconocimiento No Es Significativo" << endl << endl;
                }
            else {
                cout << "El Campo De Reconocimiento Es Significativo" << endl << endl;
                }

            cout << "PSH: " << binaryFile[380] << endl;
            if(binaryFile[380] == 0) {
                cout << "Funcion PUSH Desactivada" << endl << endl;
                }
            else {
                cout << "Funcion PUSH Activada" << endl << endl;
                }

            cout << "RST: " << binaryFile[381] << endl;
            if(binaryFile[381] == 0) {
                cout << "No Resetear La Conexion" << endl << endl;
                }
            else {
                cout << "Resetear La Conexion" << endl << endl;
                }

            cout << "SYN: " << binaryFile[382] << endl;
            if(binaryFile[382] == 0) {
                cout << "No Sincronizar Los Numeros de Secuencia" << endl << endl;
                }
            else {
                cout << "Sincronizar Los Numeros de Secuencia" << endl << endl;
                }

            cout << "FIN: " << binaryFile[383] << endl;
            if(binaryFile[383] == 0) {
                cout << "No Hay Mas Datos Del Emisor" << endl << endl;
                }
            else {
                cout << "Hay Mas Datos Del Emisor" << endl << endl;
                }

            cout << "Tamano de la ventana: ";

            convertHex[0] = fullFile[96];
            convertHex[1] = fullFile[97];
            convertHex[2] = fullFile[98];
            convertHex[3] = fullFile[99];
            convertHex[4] = '\0';
            byte = hextodec.hexadecimalToDecimal(convertHex);

            cout << byte << endl << endl;

            cout << "Checksum: ";

            convertHex[0] = fullFile[100];
            convertHex[1] = fullFile[101];
            convertHex[2] = fullFile[102];
            convertHex[3] = fullFile[103];
            convertHex[4] = '\0';
            byte = hextodec.hexadecimalToDecimal(convertHex);

            cout << byte << endl << endl;

            cout << "Checksum Verificacion: " << endl;
            int checkSumTCP = 0;
            int binaryComplementTCP = 0;
            currentPosition = 68;
            while(currentPosition < 114) {
                convertHex[0] = fullFile[currentPosition];
                convertHex[1] = fullFile[currentPosition+1];
                convertHex[2] = fullFile[currentPosition+2];
                convertHex[3] = fullFile[currentPosition+3];
                convertHex[4] = '\0';
                byte2 = hextodec.hexadecimalToDecimal(convertHex);
                if(currentPosition != 100 && currentPosition != 112) {
                    checkSumTCP = checkSumTCP + binaryFunctions.binaryComplement(byte2);
                    cout << convertHex << " : " << byte2 << " : " << binaryFunctions.binaryComplement(byte2) << endl;
                    }
                currentPosition = currentPosition + 4;
                }

            cout << checkSumTCP << " Complemento -> " << byte << endl << endl;

            cout << "Puntero Urgente: ";

            convertHex[0] = fullFile[104];
            convertHex[1] = fullFile[105];
            convertHex[2] = fullFile[106];
            convertHex[3] = fullFile[107];
            convertHex[4] = '\0';
            byte = hextodec.hexadecimalToDecimal(convertHex);

            cout << byte << endl;

            if(binaryFile[378] == 0) {
                cout << "La opcion Urgent Pointer esta Desactivada" << endl << endl;
                }

            cout << "Opciones y Relleno: ";

            convertHex[0] = fullFile[108];
            convertHex[1] = fullFile[109];
            convertHex[2] = fullFile[110];
            convertHex[3] = fullFile[111];
            convertHex[2] = fullFile[112];
            convertHex[3] = fullFile[113];
            convertHex[4] = '\0';
            byte = hextodec.hexadecimalToDecimal(convertHex);

            cout << byte << endl;

            if(byte == 0) {
                cout << "No hay opciones ni relleno" << endl << endl;
                }

            cout << endl;
            system("pause");
            }
        else if(option == 2) {
            system("cls");
            pcap_if_t *alldevs;
            pcap_if_t *d;
            int i=0;
            char errbuf[PCAP_ERRBUF_SIZE];

            if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1) {
                fprintf(stderr,"Error encontrando todos los dispositivos: %s\n", errbuf);
                exit(1);
                }

            for(d= alldevs; d != NULL; d= d->next) {
                printf("%d. %s", ++i, d->name);
                if (d->description)
                    printf(" (%s)\n", d->description);
                else
                    cout << "No hay descripcion disponible" << endl;
                }

            if (i == 0) {
                cout << endl << "No hay interfaces, Asegurese que WinPcap este instalado" << endl;
                }

            pcap_freealldevs(alldevs);
            system("pause");
            }
        else if(option == 3) {
            pcap_if_t *alldevs;
            pcap_if_t *d;
            int inum;
            int i=0;
            pcap_t *adhandle;
            char errbuf[PCAP_ERRBUF_SIZE];

            /* Retrieve the device list on the local machine */
            if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1) {
                fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
                exit(1);
                }

            /* Print the list */
            for(d=alldevs; d; d=d->next) {
                printf("%d. %s", ++i, d->name);
                if (d->description)
                    printf(" (%s)\n", d->description);
                else
                    printf(" (No description available)\n");
                }

            if(i==0) {
                printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
                return -1;
                }

            printf("Ingresa el numero de Interfaz (1-%d):",i);
            scanf("%d", &inum);

            if(inum < 1 || inum > i) {
                printf("\nInterface number out of range.\n");
                /* Free the device list */
                pcap_freealldevs(alldevs);
                return -1;
                }

            /* Jump to the selected adapter */
            for(d=alldevs, i=0; i< inum-1 ; d=d->next, i++);

            /* Open the device */
            if ( (adhandle= pcap_open(d->name,          // name of the device
                                      65536,            // portion of the packet to capture
                                      // 65536 guarantees that the whole packet will be captured on all the link layers
                                      PCAP_OPENFLAG_PROMISCUOUS,    // promiscuous mode
                                      1000,             // read timeout
                                      NULL,             // authentication on the remote machine
                                      errbuf            // error buffer
                                     ) ) == NULL) {
                fprintf(stderr,"\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
                /* Free the device list */
                pcap_freealldevs(alldevs);
                return -1;
                }

            printf("\nlistening on %s...\n", d->description);

            /* At this point, we don't need any more the device list. Free it */
            pcap_freealldevs(alldevs);

            /* start the capture */
            pcap_loop(adhandle, 0, packet_handler, NULL);
            system("pause");
            }
        else if(option == 4) {
            pcap_if_t *alldevs;
            pcap_if_t *d;
            int inum;
            int i=0;
            pcap_t *adhandle;
            int res;
            char errbuf[PCAP_ERRBUF_SIZE];
            struct tm ltime;
            char timestr[16];
            struct pcap_pkthdr *header;
            const u_char *pkt_data;
            time_t local_tv_sec;
            char character[3];
            int number = 0;
            int verify = 0;


            /* Retrieve the device list on the local machine */
            if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1) {
                fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
                exit(1);
                }

            /* Print the list */
            for(d=alldevs; d; d=d->next) {
                printf("%d. %s", ++i, d->name);
                if (d->description)
                    printf(" (%s)\n", d->description);
                else
                    printf(" (No description available)\n");
                }

            if(i==0) {
                printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
                return -1;
                }

            printf("Ingresa el numero de interfaz (1-%d):",i);
            scanf("%d", &inum);

            if(inum < 1 || inum > i) {
                printf("\nInterface number out of range.\n");
                /* Free the device list */
                pcap_freealldevs(alldevs);
                return -1;
                }

            /* Jump to the selected adapter */
            for(d=alldevs, i=0; i< inum-1 ; d=d->next, i++);

            /* Open the device */
            if ( (adhandle= pcap_open(d->name,          // name of the device
                                      65536,            // portion of the packet to capture.
                                      // 65536 guarantees that the whole packet will be captured on all the link layers
                                      PCAP_OPENFLAG_PROMISCUOUS,    // promiscuous mode
                                      1000,             // read timeout
                                      NULL,             // authentication on the remote machine
                                      errbuf            // error buffer
                                     ) ) == NULL) {
                fprintf(stderr,"\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
                /* Free the device list */
                pcap_freealldevs(alldevs);
                return -1;
                }

            printf("\nlistening on %s...\n", d->description);

            /* At this point, we don't need any more the device list. Free it */
            pcap_freealldevs(alldevs);

            /* Retrieve the packets */
            while((res = pcap_next_ex( adhandle, &header, &pkt_data)) >= 0 && verify < 1) {

                if(res == 0)
                    /* Timeout elapsed */
                    continue;

                /* convert the timestamp to readable format */
                local_tv_sec = header->ts.tv_sec;
                localtime(&local_tv_sec);
                strftime( timestr, sizeof timestr, "%H:%M:%S", &ltime);

                printf("%s,%.6d len:%d\n", timestr, header->ts.tv_usec, header->len);

                for(int i=0; i<1000; i++) {
                    binaryFile[i] = 0;
                    }

                int currentRead = 0;
                for(int i=0; i<1000; i=i+8) {
                    byte = pkt_data[currentRead];
                    if(byte >= 128) {
                        binaryFile[i] = 1;
                        byte = byte - 128;
                        }
                    if(byte >= 64) {
                        binaryFile[i+1] = 1;
                        byte = byte - 64;
                        }
                    if(byte >= 32) {
                        binaryFile[i+2] = 1;
                        byte = byte - 32;
                        }
                    if(byte >= 16) {
                        binaryFile[i+3] = 1;
                        byte = byte - 16;
                        }
                    if(byte >= 8) {
                        binaryFile[i+4] = 1;
                        byte = byte - 8;
                        }
                    if(byte >= 4) {
                        binaryFile[i+5] = 1;
                        byte = byte - 4;
                        }
                    if(byte >= 2) {
                        binaryFile[i+6] = 1;
                        byte = byte - 2;
                        }
                    if(byte >= 1) {
                        binaryFile[i+7] = 1;
                        byte = byte - 1;
                        }
                    currentRead = currentRead + 1;
                    }

                verify++;
                }

            int j = 0;
            char x;
            for(int i=0; i<1000; i=i+4) {
                int currentWord = 0;
                if(binaryFile[i] == 1) {
                    currentWord = currentWord + 8;
                    }
                if(binaryFile[i+1] == 1) {
                    currentWord = currentWord + 4;
                    }
                if(binaryFile[i+2] == 1) {
                    currentWord = currentWord + 2;
                    }
                if(binaryFile[i+3] == 1) {
                    currentWord = currentWord + 1;
                    }

                switch(currentWord) {
                    case 0:
                        x = '0';
                        break;
                    case 1:
                        x = '1';
                        break;
                    case 2:
                        x = '2';
                        break;
                    case 3:
                        x = '3';
                        break;
                    case 4:
                        x = '4';
                        break;
                    case 5:
                        x = '5';
                        break;
                    case 6:
                        x = '6';
                        break;
                    case 7:
                        x = '7';
                        break;
                    case 8:
                        x = '8';
                        break;
                    case 9:
                        x = '9';
                        break;
                    case 10:
                        x = 'A';
                        break;
                    case 11:
                        x = 'B';
                        break;
                    case 12:
                        x = 'C';
                        break;
                    case 13:
                        x = 'D';
                        break;
                    case 14:
                        x = 'E';
                        break;
                    case 15:
                        x = 'F';
                        break;
                    default:
                        cout << "Valor no valido" << endl;
                    }

                fullFile[j] = x;
                j++;
                }

            ofstream wifiFile("wififile.txt");

            if(!wifiFile.good()){
                cout << "No se pudo abrir el archivo" << endl;
            }

            i = 0;
            while(i < 500){
                wifiFile.write((char*)&fullFile[i],sizeof(char));
                i++;
            }

            wifiFile.close();

            cout << "Direccion MAC Origen: " << fullFile[0] << fullFile[1];
            cout << ":" << fullFile[2] << fullFile[3];
            cout << ":" << fullFile[4] << fullFile[5];
            cout << ":" << fullFile[6] << fullFile[7];
            cout << ":" << fullFile[8] << fullFile[9];
            cout << ":" << fullFile[10] << fullFile[11];
            cout << endl;

            cout << "Direccion MAC Destino: " << fullFile[12] << fullFile[13];
            cout << ":" << fullFile[14] << fullFile[15];
            cout << ":" << fullFile[16] << fullFile[17];
            cout << ":" << fullFile[18] << fullFile[19];
            cout << ":" << fullFile[20] << fullFile[21];
            cout << ":" << fullFile[22] << fullFile[23];
            cout << endl << endl;

            protocol[0] = fullFile[24];
            protocol[1] = fullFile[25];
            protocol[2] = fullFile[26];
            protocol[3] = fullFile[27];
            protocol[4] = '\0';

            cout << "Protocolo: " << protocol << endl;
            cout << "------TABLA DE PROTOCOLOS------" << endl;
            cout << "      0800      |     IP_V4    " << endl;
            cout << "      86DD      |     IP_V6    " << endl;
            cout << "      0600      | XEROX NS IDP " << endl;
            cout << "      0801      | X.75 Internet" << endl;
            cout << "      0802      | NBS Internet " << endl;
            cout << "      0806      |      ARP     " << endl;
            cout << "      80F3      |      AARP    " << endl;
            cout << endl << endl;

            if(strcmp(protocol,"0800") == 0) {
                cout << "El protocolo encapsulado corresponde a IP_V4" << endl;
                cout << "Type: IP_V4 " << "Con el codigo: " << protocol << endl << endl;
                cout << "__________CABECERA IP__________" << endl << endl;
                }
            else if(strcmp(protocol,"86DD") == 0) {
                cout << "El protocolo encapsulado corresponde a IP_V6" << endl;
                cout << "Type: IP_V6" << endl << endl;
                cout << "Se esta desarrollando" << endl;
                system("pause");
                }
            else if(strcmp(protocol,"0600") == 0) {
                cout << "El protocolo encapsulado corresponde a XEROX NS IPD" << endl;
                cout << "Type: XEROX NS IDP" << endl << endl;
                cout << "Se esta desarrollando" << endl;
                system("pause");
                }
            else if(strcmp(protocol,"0801") == 0) {
                cout << "El protocolo encapsulado corresponde a X.75 Internet" << endl;
                cout << "Type: X.75 Internet" << endl << endl;
                cout << "Se esta desarrollando" << endl;
                system("pause");
                }
            else if(strcmp(protocol,"0802") == 0) {
                cout << "El protocolo encapsulado corresponde a NBS Internet" << endl;
                cout << "Type: NBS Internet" << endl << endl;
                cout << "Se esta desarrollando" << endl;
                system("pause");
                }
            else if(strcmp(protocol,"0806") == 0) {
                cout << "El protocolo encapsulado corresponde a ARP" << endl;
                cout << "Type: ARP" << endl << endl;
                cout << "Se esta desarrollando" << endl;
                system("pause");
                }
            else if(strcmp(protocol,"80F3") == 0) {
                cout << "El protocolo encapsulado corresponde a AARP" << endl;
                cout << "Type: AARP" << endl << endl;
                cout << "Se esta desarrollando" << endl;
                system("pause");
                }
            else {
                cout << "El protocolo encapsulado no esta definido" << endl;
                system("pause");
                }

            cout << "Version y Longitud: " << endl;

            convertHex[0] = fullFile[28];
            convertHex[1] = '\0';

            byte = atoi(convertHex);

            cout << "Version: " << convertHex[0] << endl;
            cout << "Longitud: " << convertHex[0];

            convertHex[0] = fullFile[29];
            convertHex[1] = '\0';

            byte2 = atoi(convertHex);

            cout << " * " << convertHex[0] << " = " << byte*byte2 << " BYTES" << endl << endl;

            cout << "Tipo de Servicio:    ";

            initialPosition = 120;
            for(int i=0; i<8; i++) {
                verifyServiceType[i] = binaryFile[initialPosition];
                initialPosition++;
                }

            for(int i=0; i<8; i++) {
                cout << verifyServiceType[i] << ".";
                }
            cout << endl;

            if(verifyServiceType[0] == 0 && verifyServiceType[1] == 0 &&
                    verifyServiceType[2] == 0) {
                cout << "Precedencia: Rutina" << endl;
                }
            else if(verifyServiceType[0] == 0 && verifyServiceType[1] == 0 &&
                    verifyServiceType[2] == 1) {
                cout << "Precedencia: Prioridad" << endl;
                }
            else {
                cout << "Precedencia: No definida" << endl;
                }

            if(verifyServiceType[3] == 0 && verifyServiceType[4] == 0 &&
                    verifyServiceType[5] == 0 && verifyServiceType[6] == 0) {
                cout << "Tipo de Servicio: Normal" << endl;
                }
            else if(verifyServiceType[3] == 1 && verifyServiceType[4] == 0 &&
                    verifyServiceType[5] == 0 && verifyServiceType[6] == 0) {
                cout << "Tipo de Servicio: Minimizar Retardo" << endl;
                }
            else {
                cout << "Tipo de Servicio: No definido" << endl;
                }

            if(verifyServiceType[7] == 0) {
                cout << "Must Be Zero: 0" << endl << endl;
                }
            else {
                cout << "Must Be Zero: 1" << endl << endl;
                }

            cout << "Longitud Total del Paquete: ";

            convertHex[0] = fullFile[32];
            convertHex[1] = fullFile[33];
            convertHex[2] = fullFile[34];
            convertHex[3] = fullFile[35];
            convertHex[4] = '\0';
            byte = hextodec.hexadecimalToDecimal(convertHex);

            cout << byte << " Bytes" << endl << endl;

            cout << "Identificacion: ";

            convertHex[0] = fullFile[36];
            convertHex[1] = fullFile[37];
            convertHex[2] = fullFile[38];
            convertHex[3] = fullFile[39];
            convertHex[4] = '\0';

            cout << "x" << convertHex << endl << endl;

            cout << "Banderas:      ";

            initialPosition = 160;
            for(int i=0; i<3; i++) {
                verifyCurrentBits[i] = binaryFile[initialPosition];
                initialPosition++;
                }

            for(int i=0; i<3; i++) {
                cout << verifyCurrentBits[i] << ".";
                }
            cout << endl;

            cout << "Reservado: " << verifyCurrentBits[0] << endl;
            cout << "Dont Fragment: " << verifyCurrentBits[1] << endl;
            cout << "More Fragments: " << verifyCurrentBits[2] << endl << endl;

            cout << "Desplazamiento: " << endl;

            if(binaryFile[162] == 0) {
                cout << "No hay desplazamiento" << endl << endl;
                }
            else {
                int totalDisplacement = 0;
                if(binaryFile[163] == 1) {
                    totalDisplacement = totalDisplacement + 4096;
                    }
                if(binaryFile[164] == 1) {
                    totalDisplacement = totalDisplacement + 2048;
                    }
                if(binaryFile[165] == 1) {
                    totalDisplacement = totalDisplacement + 1024;
                    }
                if(binaryFile[166] == 1) {
                    totalDisplacement = totalDisplacement + 512;
                    }
                if(binaryFile[167] == 1) {
                    totalDisplacement = totalDisplacement + 256;
                    }
                if(binaryFile[168] == 1) {
                    totalDisplacement = totalDisplacement + 128;
                    }
                if(binaryFile[169] == 1) {
                    totalDisplacement = totalDisplacement + 64;
                    }
                if(binaryFile[170] == 1) {
                    totalDisplacement = totalDisplacement + 32;
                    }
                if(binaryFile[171] == 1) {
                    totalDisplacement = totalDisplacement + 16;
                    }
                if(binaryFile[172] == 1) {
                    totalDisplacement = totalDisplacement + 8;
                    }
                if(binaryFile[173] == 1) {
                    totalDisplacement = totalDisplacement + 4;
                    }
                if(binaryFile[174] == 1) {
                    totalDisplacement = totalDisplacement + 2;
                    }
                if(binaryFile[175] == 1) {
                    totalDisplacement = totalDisplacement + 1;
                    }

                cout << totalDisplacement << "Bytes Para el Proximo Paquete" << endl << endl;
                }

            cout << "Tiempo de vida: ";

            convertHex[0] = fullFile[44];
            convertHex[1] = fullFile[45];
            convertHex[2] = '\0';
            byte = hextodec.hexadecimalToDecimal(convertHex);

            cout << byte << " segundos" << endl << endl;

            protocol[0] = fullFile[46];
            protocol[1] = fullFile[47];
            protocol[2] = '\0';
            cout << "Protocolo: " << protocol << endl;
            byte = hextodec.hexadecimalToDecimal(convertHex);

            cout << "------TABLA DE PROTOCOLOS------" << endl;
            cout << "       01       |     ICMP    " << endl;
            cout << "       06       |     TCP    " << endl;
            cout << "       17       |     UDP    " << endl;

            cout << endl << endl;

            if(strcmp(protocol,"06") == 0) {
                cout << "El protocolo encapsulado corresponde a TCP" << endl;
                cout << "Protocolo: TCP, Con el codigo: 06, (Transmission Control)" << endl << endl;
                }
            else if(strcmp(protocol,"01") == 0) {
                cout << "El protocolo encapsulado corresponde a ICMP" << endl;
                cout << "Protocolo: ICMP, Con el codigo: 01, EN DESARROLLO" << endl << endl;
                system("pause");
                }
            else if(strcmp(protocol,"17") == 0) {
                cout << "El protocolo encapsulado corresponde a UDP" << endl;
                cout << "Protocolo: UDP, Con el codigo: 17, EN DESARROLLO" << endl << endl;
                system("pause");
                }
            else {
                cout << "Protocolo no definido" << endl;
                system("pause");
                }

            cout << "Checksum: ";

            convertHex[0] = fullFile[48];
            convertHex[1] = fullFile[49];
            convertHex[2] = fullFile[50];
            convertHex[3] = fullFile[51];
            convertHex[4] = '\0';
            byte = hextodec.hexadecimalToDecimal(convertHex);

            cout << byte << endl;

            cout << "Checksum Verificacion: " << endl;
            int checkSumIP = 0;
            int binaryComplementIP = 0;
            int currentPosition = 28;
            while(currentPosition < 68) {
                convertHex[0] = fullFile[currentPosition];
                convertHex[1] = fullFile[currentPosition+1];
                convertHex[2] = fullFile[currentPosition+2];
                convertHex[3] = fullFile[currentPosition+3];
                convertHex[4] = '\0';
                byte2 = hextodec.hexadecimalToDecimal(convertHex);
                if(currentPosition != 48) {
                    checkSumIP = checkSumIP + binaryFunctions.binaryComplement(byte2);
                    cout << convertHex << " : " << byte2 << " : " << binaryFunctions.binaryComplement(byte2) << endl;
                    }
                currentPosition = currentPosition + 4;
                }

            //cout << checkSumIP << " Complemento -> " << byte << endl << endl;
            cout << checkSumIP << " Complemento -> " << binaryFunctions.binaryComplement(checkSumIP) << endl << endl;

            cout << "Direccion IP Origen: ";

            convertHex[0] = fullFile[52];
            convertHex[1] = fullFile[53];
            convertHex[2] = '\0';
            byte = hextodec.hexadecimalToDecimal(convertHex);

            cout << byte << ".";

            convertHex[0] = fullFile[54];
            convertHex[1] = fullFile[55];
            convertHex[2] = '\0';
            byte = hextodec.hexadecimalToDecimal(convertHex);

            cout << byte << ".";

            convertHex[0] = fullFile[56];
            convertHex[1] = fullFile[57];
            convertHex[2] = '\0';
            byte = hextodec.hexadecimalToDecimal(convertHex);

            cout << byte << ".";

            convertHex[0] = fullFile[58];
            convertHex[1] = fullFile[59];
            convertHex[2] = '\0';
            byte = hextodec.hexadecimalToDecimal(convertHex);

            cout << byte << "." << endl << endl;

            cout << "Direccion IP Destino: ";

            convertHex[0] = fullFile[60];
            convertHex[1] = fullFile[61];
            convertHex[2] = '\0';
            byte = hextodec.hexadecimalToDecimal(convertHex);

            cout << byte << ".";

            convertHex[0] = fullFile[62];
            convertHex[1] = fullFile[63];
            convertHex[2] = '\0';
            byte = hextodec.hexadecimalToDecimal(convertHex);

            cout << byte << ".";

            convertHex[0] = fullFile[64];
            convertHex[1] = fullFile[65];
            convertHex[2] = '\0';
            byte = hextodec.hexadecimalToDecimal(convertHex);

            cout << byte << ".";

            convertHex[0] = fullFile[66];
            convertHex[1] = fullFile[67];
            convertHex[2] = '\0';
            byte = hextodec.hexadecimalToDecimal(convertHex);

            cout << byte << "." << endl << endl;



            cout << "__________CABECERA TCP__________" << endl << endl;

            cout << "Direccion de puerto origen: ";

            convertHex[0] = fullFile[68];
            convertHex[1] = fullFile[69];
            convertHex[2] = fullFile[70];
            convertHex[3] = fullFile[71];
            convertHex[4] = '\0';
            byte = hextodec.hexadecimalToDecimal(convertHex);

            cout << byte << endl << endl;

            cout << "Direccion de Puerto Destino: ";

            convertHex[0] = fullFile[72];
            convertHex[1] = fullFile[73];
            convertHex[2] = fullFile[74];
            convertHex[3] = fullFile[75];
            convertHex[4] = '\0';
            byte = hextodec.hexadecimalToDecimal(convertHex);

            cout << byte << endl << endl;

            cout << "Numero de Secuencia: ";

            convertHex[0] = fullFile[76];
            convertHex[1] = fullFile[77];
            convertHex[2] = fullFile[78];
            convertHex[3] = fullFile[79];
            convertHex[4] = fullFile[80];
            convertHex[5] = fullFile[81];
            convertHex[6] = fullFile[82];
            convertHex[7] = fullFile[83];
            convertHex[8] = '\0';
            byte = hextodec.hexadecimalToDecimal(convertHex);

            cout << byte << endl << endl;

            cout << "Numero de Confirmacion: ";

            convertHex[0] = fullFile[84];
            convertHex[1] = fullFile[85];
            convertHex[2] = fullFile[86];
            convertHex[3] = fullFile[87];
            convertHex[4] = fullFile[88];
            convertHex[5] = fullFile[89];
            convertHex[6] = fullFile[90];
            convertHex[7] = fullFile[91];
            convertHex[8] = '\0';
            byte = hextodec.hexadecimalToDecimal(convertHex);

            cout << byte << endl << endl;

            cout << "Longitud de la cabecera: ";

            int tcpSize = 0;
            if(binaryFile[368] == 1) {
                tcpSize = tcpSize + 8;
                }
            if(binaryFile[369] == 1) {
                tcpSize = tcpSize + 4;
                }
            if(binaryFile[370] == 1) {
                tcpSize = tcpSize + 2;
                }
            if(binaryFile[371] == 1) {
                tcpSize = tcpSize + 1;
                }

            cout << tcpSize << endl << endl;
            cout << tcpSize << " * 4 = " << tcpSize*4 << " BYTES" << endl << endl;

            cout << "Reservados: ";
            initialPosition = 372;
            for(int i=0; i<6; i++) {
                cout << binaryFile[initialPosition + i] << ".";
                }
            cout << endl << endl;

            cout << "Banderas: " ;
            initialPosition = 378;
            for(int i=0; i<6; i++) {
                cout << binaryFile[initialPosition + i] << ".";
                }
            cout << endl;

            cout << "Nonce: " << binaryFile[378] << endl;
            if(binaryFile[375] == 0) {
                cout << "Nonce No Es Significativo" << endl << endl;
                }
            else {
                cout << "Nonce Es Significativo" << endl << endl;
                }

            cout << "CWR: " << binaryFile[378] << endl;
            if(binaryFile[376] == 0) {
                cout << "Congestion Windows Reduced No Es Significativo" << endl << endl;
                }
            else {
                cout << "Congestion Windows Reduced Es Significativo" << endl << endl;
                }

            cout << "ECN-Echo: " << binaryFile[378] << endl;
            if(binaryFile[377] == 0) {
                cout << "ECN-Echo No Es Significativo" << endl << endl;
                }
            else {
                cout << "ECN-Echo Es Significativo" << endl << endl;
                }

            cout << "URG: " << binaryFile[378] << endl;
            if(binaryFile[378] == 0) {
                cout << "Urgent Pointer No Es Significativo" << endl << endl;
                }
            else {
                cout << "Urgent Pointer Es Significativo" << endl << endl;
                }

            cout << "ACK: " << binaryFile[379] << endl;
            if(binaryFile[379] == 0) {
                cout << "El Campo De Reconocimiento No Es Significativo" << endl << endl;
                }
            else {
                cout << "El Campo De Reconocimiento Es Significativo" << endl << endl;
                }

            cout << "PSH: " << binaryFile[380] << endl;
            if(binaryFile[380] == 0) {
                cout << "Funcion PUSH Desactivada" << endl << endl;
                }
            else {
                cout << "Funcion PUSH Activada" << endl << endl;
                }

            cout << "RST: " << binaryFile[381] << endl;
            if(binaryFile[381] == 0) {
                cout << "No Resetear La Conexion" << endl << endl;
                }
            else {
                cout << "Resetear La Conexion" << endl << endl;
                }

            cout << "SYN: " << binaryFile[382] << endl;
            if(binaryFile[382] == 0) {
                cout << "No Sincronizar Los Numeros de Secuencia" << endl << endl;
                }
            else {
                cout << "Sincronizar Los Numeros de Secuencia" << endl << endl;
                }

            cout << "FIN: " << binaryFile[383] << endl;
            if(binaryFile[383] == 0) {
                cout << "No Hay Mas Datos Del Emisor" << endl << endl;
                }
            else {
                cout << "Hay Mas Datos Del Emisor" << endl << endl;
                }

            cout << "Tamano de la ventana: ";

            convertHex[0] = fullFile[96];
            convertHex[1] = fullFile[97];
            convertHex[2] = fullFile[98];
            convertHex[3] = fullFile[99];
            convertHex[4] = '\0';
            byte = hextodec.hexadecimalToDecimal(convertHex);

            cout << byte << endl << endl;

            cout << "Checksum: ";

            convertHex[0] = fullFile[100];
            convertHex[1] = fullFile[101];
            convertHex[2] = fullFile[102];
            convertHex[3] = fullFile[103];
            convertHex[4] = '\0';
            byte = hextodec.hexadecimalToDecimal(convertHex);

            cout << byte << endl << endl;

            cout << "Checksum Verificacion: " << endl;
            int checkSumTCP = 0;
            int binaryComplementTCP = 0;
            currentPosition = 68;
            while(currentPosition < 114) {
                convertHex[0] = fullFile[currentPosition];
                convertHex[1] = fullFile[currentPosition+1];
                convertHex[2] = fullFile[currentPosition+2];
                convertHex[3] = fullFile[currentPosition+3];
                convertHex[4] = '\0';
                byte2 = hextodec.hexadecimalToDecimal(convertHex);
                if(currentPosition != 100 && currentPosition != 112) {
                    checkSumTCP = checkSumTCP + binaryFunctions.binaryComplement(byte2);
                    cout << convertHex << " : " << byte2 << " : " << binaryFunctions.binaryComplement(byte2) << endl;
                    }
                currentPosition = currentPosition + 4;
                }

            cout << checkSumTCP << " Complemento -> " << byte << endl << endl;

            cout << "Puntero Urgente: ";

            convertHex[0] = fullFile[104];
            convertHex[1] = fullFile[105];
            convertHex[2] = fullFile[106];
            convertHex[3] = fullFile[107];
            convertHex[4] = '\0';
            byte = hextodec.hexadecimalToDecimal(convertHex);

            cout << byte << endl;

            if(binaryFile[378] == 0) {
                cout << "La opcion Urgent Pointer esta Desactivada" << endl << endl;
                }

            cout << "Opciones y Relleno: ";

            convertHex[0] = fullFile[108];
            convertHex[1] = fullFile[109];
            convertHex[2] = fullFile[110];
            convertHex[3] = fullFile[111];
            convertHex[2] = fullFile[112];
            convertHex[3] = fullFile[113];
            convertHex[4] = '\0';
            byte = hextodec.hexadecimalToDecimal(convertHex);

            cout << byte << endl;

            if(byte == 0) {
                cout << "No hay opciones ni relleno" << endl << endl;
                }

            if(res == -1) {
                printf("Error reading the packets: %s\n", pcap_geterr(adhandle));
                return -1;
                }
            system("pause");
            }
        else if(option == 6) {
            pcap_t *handle;			/* Session handle */
            char *dev;			/* The device to sniff on */
            char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
            struct bpf_program fp;		/* The compiled filter */
            char filter_exp[] = "port 42222";	/* The filter expression */
            bpf_u_int32 mask;		/* Our netmask */
            bpf_u_int32 net;		/* Our IP */
            struct pcap_pkthdr header;	/* The header that pcap gives us */
            const u_char *packet;		/* The actual packet */

            /* Define the device */
            dev = pcap_lookupdev(errbuf);
            if (dev == NULL) {
                fprintf(stderr, "No se pudo abrir el dispositivo: %s\n", errbuf);
                return(2);
                }
            /* Find the properties for the device */
            if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
                fprintf(stderr, "No se pudo abrir la netmask %s: %s\n", dev, errbuf);
                net = 0;
                mask = 0;
                }
            /* Open the session in promiscuous mode */
            handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
            if (handle == NULL) {
                fprintf(stderr, "No se pudo abrir el dispositivo %s: %s\n", dev, errbuf);
                return(2);
                }
            /* Compile and apply the filter */
            if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
                fprintf(stderr, "No se pudo filtrar %s: %s\n", filter_exp, pcap_geterr(handle));
                return(2);
                }
            if (pcap_setfilter(handle, &fp) == -1) {
                fprintf(stderr, "No se pudo filtrar %s: %s\n", filter_exp, pcap_geterr(handle));
                return(2);
                }
            /* Grab a packet */
            packet = pcap_next(handle, &header);
            /* Print its length */
            printf("Capturado un paquete de longitud [%d]\n", header.len);
            /* And close the session */
            pcap_close(handle);
            system("pause");
            }
        else if(option == 5) {
            finish = 1;
            }
        }
    return 0;
    }

void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data) {
    struct tm ltime;
    char timestr[16];
    time_t local_tv_sec;

    /*
     * unused variables
     */
    (VOID)(param);
    (VOID)(pkt_data);

    /* convert the timestamp to readable format */
    local_tv_sec = header->ts.tv_sec;
    localtime(&local_tv_sec);
    strftime( timestr, sizeof timestr, "%H:%M:%S", &ltime);

    printf("%s,%.6d len:%d\n", timestr, header->ts.tv_usec, header->len);
    }
