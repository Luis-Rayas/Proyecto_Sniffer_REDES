#include <iostream>
#include <pcap.h>
#include <dirent.h>
#include <fstream>

#include <stdlib.h>
#include <stdio.h>

#include "trama.h"

#define LINE_LEN 16

using namespace std;

int capturaEnTiempoReal(int argc, char **argv);
void capturaDesdeArchivo();
void recuperar();

int main(int argc, char **argv)
{
    int opc;

    do
    {
        cout << endl << endl << "♡♡🧸\t Sniffer \t🧸♡♡" << endl << endl;
        cout << "Menu" << endl;
        cout << "1. Captura de datos en tiempo Real" << endl;
        cout << "2. Lectura de un archivo .bin" << endl;
        cout << "3. Salir" << endl;
        cin >> opc;
        fflush(stdin);
        switch(opc)
        {
        case 1:
            capturaEnTiempoReal(argc, argv);
            break;
        case 2:
            capturaDesdeArchivo();
            break;
        case 3:
            cout << "Hasta pronto!" << endl;
            break;
        default:
            cout << "Ingrese una opcion correcta..." << endl;
            break;
        }
        cout << endl;
        system("pause");
        system("cls");
    }
    while(opc != 3);
    return 0;
}

int capturaEnTiempoReal(int argc, char **argv)
{
    int contador(0), maxPaquetes(5);
    pcap_if_t *alldevs, *d;
    pcap_t *fp;
    u_int inum, i=0;
    char errbuf[PCAP_ERRBUF_SIZE];
    int res;
    struct pcap_pkthdr *header;
    const u_char *pkt_data;

    cout << "Cuantos paquetes desea recibir?" << endl;
    cin >> maxPaquetes;
    if(maxPaquetes < 0){
        cout << "Numero de paquetes maximo invalido, seleccionando 5 por defecto..." << endl;
        maxPaquetes = 5;
    }

    //ofstream file("temp.bin", ios::out);//Se crea el archivo

    printf("pktdump_ex: prints the packets of the network using WinPcap.\n");
    printf("   Usage: pktdump_ex [-s source]\n\n"
           "   Examples:\n"
           "      pktdump_ex -s file.acp\n"
           "      pktdump_ex -s \\Device\\NPF_{C8736017-F3C3-4373-94AC-9A34B7DAD998}\n\n");

    if(argc < 3)
    {
        printf("\nNo adapter selected: printing the device list:\n");
        /* The user didn't provide a packet source: Retrieve the local device list */
        if(pcap_findalldevs(&alldevs, errbuf) == -1)
        {
            fprintf(stderr,"Error in pcap_findalldevs_ex: %s\n", errbuf);
            exit(1);
        }

        /* Print the list */
        for(d=alldevs; d; d=d->next)
        {
            printf("%d. %s\n    ", ++i, d->name);

            if (d->description)
                printf(" (%s)\n", d->description);
            else
                printf(" (No description available)\n");
        }

        if (i==0)
        {
            printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
            return -1;
        }

        printf("Enter the interface number (1-%d):",i);
        scanf("%d", &inum);

        if (inum < 1 || inum > i)
        {
            printf("\nInterface number out of range.\n");

            /* Free the device list */
            pcap_freealldevs(alldevs);
            return -1;
        }

        /* Jump to the selected adapter */
        for (d=alldevs, i=0; i< inum-1 ; d=d->next, i++);

        /* Open the adapter */
        if ((fp = pcap_open_live(d->name,	// name of the device
                                 65536,							// portion of the packet to capture.
                                 // 65536 grants that the whole packet will be captured on all the MACs.
                                 1,								// promiscuous mode (nonzero means promiscuous)
                                 1000,							// read timeout
                                 errbuf							// error buffer
                                )) == NULL)
        {
            fprintf(stderr,"\nError opening adapter\n");
            return -1;
        }
    }
    else
    {
        /* Do not check for the switch type ('-s') */
        if ((fp = pcap_open_live(argv[2],	// name of the device
                                 65536,							// portion of the packet to capture.
                                 // 65536 grants that the whole packet will be captured on all the MACs.
                                 1,								// promiscuous mode (nonzero means promiscuous)
                                 1000,							// read timeout
                                 errbuf							// error buffer
                                )) == NULL)
        {
            fprintf(stderr,"\nError opening adapter\n");
            return -1;
        }
    }



    /* Read the packets */
    while((res = pcap_next_ex( fp, &header, &pkt_data)) >= 0)
    {
        Trama t;
        if(res == 0)
            /* Timeout elapsed */
            continue;

        /* print pkt timestamp and pkt len */
        //printf("%ld:%ld (%ld)\n", header->ts.tv_sec, header->ts.tv_usec, header->len);

        //if (file.is_open())
        //{
            //Print the packet
            for (i=1; (i < header->caplen + 1 ) ; i++)
            {
                //file << pkt_data[i-1];
                unsigned char dato = pkt_data[i-1];
                t.setArrBytes(dato);

            }
            /*printf("%.2x ", pkt_data[i-1]);
            if ( (i % LINE_LEN) == 0) printf("\n");*/
        //} else {
        t.ethernet();
            cout << "===================================================" << endl;
        //}
        //file.close();//Se cierra el arcivo
        //recuperar();

        printf("\n\n");
        contador++;
        if(contador == maxPaquetes)
        {
            break;
        }
    }

    if(res == -1)
    {
        printf("Error reading the packets: %s\n", pcap_geterr(fp));
        return -1;
    }

    pcap_close(fp);
    return 0;
}

void capturaDesdeArchivo()
{
    Trama t;
    FILE* archivo;
    string nombreArchivo = "Paquetes Redes\\";
    string aux;
    unsigned char dato;

    DIR* dir;
    dirent *ent;
    if (DIR* dir = opendir("Paquetes Redes"))
    {
        while (dirent* ent = readdir(dir) )
            cout << ent->d_name << '\n';
        closedir (dir);
    }

    cout << endl << "Ingrese el nombre del archivo a abrir:" << endl;
    getline(cin, aux);
    nombreArchivo += aux;
    fflush(stdin);
    archivo = fopen(nombreArchivo.c_str(), "rb");

    if (archivo == NULL)
        printf("Error al abrir el archivo\n");
    else
    {
        while(!feof(archivo))
        {
            dato = getc(archivo);
            t.setArrBytes(dato);
        }
        cout << endl;
        t.ethernet();
    }
    fclose(archivo);
}

void recuperar()
{
    FILE* archivo = fopen("temp.bin", "rb");
    Trama t;
    unsigned char dato;

    if (archivo == NULL)
        printf("Error al abrir el archivo\n");
    else
    {
        while(!feof(archivo))
        {
            dato = getc(archivo);
            t.setArrBytes(dato);
        }
        cout << endl;
        t.ethernet();
    }
    fclose(archivo);
}
