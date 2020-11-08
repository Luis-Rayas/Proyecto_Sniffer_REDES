#include "trama.h"

using namespace std;

Trama::Trama(){
    auxI1 = 0;
}
Trama::Trama(const Trama &t){ }
Trama& Trama::operator=(const Trama &t){ }

void Trama::setArrBytes(unsigned char byte, int contadorByte){
    bytes.push_back(byte);
}

int Trama::btodecimal(int aux){
    auxS1 = "";
    auxS1 = c.convert(bytes[aux], 0, 7);
    auxI1 = c.stringbinario_decimal(auxS1);
    return auxI1;
}

int Trama::b2todecimal(int aux){
    auxS2 = "";
    auxS1 = c.convert(bytes[aux], 0, 7);
    auxS2 += auxS1;
    auxS1 = c.convert(bytes[aux+1], 0, 7);
    auxS2 += auxS1;
    auxI1 = c.stringbinario_decimal(auxS2);
    return auxI1;
}

void Trama::ethernet(){
    c.imprimir_hexadecimal(0, 5,1,1, "Direccion de origen: ", bytes);
    c.imprimir_hexadecimal(6, 11,1,1, "Direccion de destino: ",bytes);
    c.imprimir_hexadecimal(12, 13,0,0, "Tipo: ",bytes);
    tipoDeCodigoEthernet();
}

void Trama::tipoDeCodigoEthernet(){
    auxI1 += bytes[12] + bytes[13];

        switch(auxI1){
            case 8:
                cout<<"-> IPv4 ";
                ipv4();
                break;
            case 14:
                cout<<"-> ARP ";
                ARP();
                break;
            case 181:
                cout<<"-> RARP ";
                RARP();
                break;
            case 355:
                cout<<"-> IPv6 ";
                IPv6();

    }
}

void Trama::ipv4(){
    version_tamanio();
    tipodeServicio();
    cout << "Longitud total: " << b2todecimal(16) << " bytes" << endl;
    cout << "Identificador: " << btodecimal(18) + btodecimal(19) << endl;
    flags();
    cout << "Posicion del fragmento: " << posicionFragmento() << endl;
    cout << "Tiempo de vida: " << btodecimal(22) << endl;
    protocolo(23);
    checksum(24, "IPv4");
    IP_imprimir(26, "IP Origen: "); 
    IP_imprimir(30, "IP Destino: ");
    imprimirResto(54);
}

void Trama::version_tamanio(){

    auxS1 = c.convert(bytes[14], 4,7);
    if(auxS1 == "0100"){
        auxS2 = c.convert(bytes[14], 4,7);
        cout << "Version: IPv4" << endl;
        auxI1 = c.stringbinario_decimal(auxS2);
        cout<< "Tamanio de cabecera: " << auxI1*4 << " bytes" << endl;
       
    }
    if(auxS1 == "0110"){
        cout << "Version: IPv6" << endl;
    }
    
}

void Trama::tipodeServicio(){
    auxS2 = c.convert(bytes[15], 0, 2);
    auxI1 = c.stringbinario_decimal(auxS2);

    cout << "Tipo de Servicio" << endl;
    cout << "Prioridad: " << auxI1 << " ";

    switch(auxI1){
        case 0:
            cout << " ->  " << "De rutina";
            break;
        case 1:
            cout << " ->  "  << "Prioritario";
            break;
        case 2:
            cout << " ->  "  << "Inmediato";
            break;
        case 3:
            cout << " ->  "  << "Relampago";
            break;
        case 4:
            cout << " ->  "  << "Invalidacion relampago";
            break;
        case 5:
            cout << " ->  "  << "Procesando llamada critica";
            break;
        case 6:
            cout << " ->  "  << "Control de trabajo de Internet";
            break;
        case 7:
            cout << " ->  "  << "Control de red";
    }

    cout << endl;
    auxS1 = c.convert(bytes[15],3,5);

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
    auxS1 = c.convert(bytes[20], 4, 0) + c.convert(bytes[21], 0, 7);;
    auxI1 = c.stringbinario_decimal(auxS1);
    return auxI1;
}

void Trama::protocolo(int byte){
    cout << "Protocolo siguiente:" << endl << "    ";
    switch(btodecimal(byte)){
    case 1:
        cout << auxI1 << ". ICMP v4" << endl;
        ICMPv4();
        break;
    case 6:
        cout << auxI1 << ". TCP" << endl;
        auxS1 = c.convert(bytes[14], 4,7);
        if(auxS1 == "0100"){//IPv4   
            TCP(34);    
        }
        if(auxS1 == "0110"){ //IPv6
            TCP(54);
        } 
        break;
    case 17:
        cout << auxI1 << ". UDP" << endl;
        break;
    case 58:
        cout << auxI1 << ". ICMP v6" << endl;
        ICMPv6();
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
    cout << ip;
    int direccionOrigen;
    for(int i = 0; i<4; i++){
        auxS1 = c.convert(bytes[x++], 0, 7);
        auxI1 = c.stringbinario_decimal(auxS1);
        cout<<auxI1<<".";
     }
    cout<<"\b \n";
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
    switch (btodecimal(34))
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
    switch (btodecimal(35))
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
        cout << "No se puede llegar a la red destino debido al tipo de Servicio" << endl;
        break;
    case 12:
        cout << "No se puede llegar al host destino debido al tipo de Servicio" << endl;
        break;
    default:
        cout << "Codigo de error ICMPv4 no reconocido..." << endl;
    }
}

void Trama::ARP(){
    cout << "\nTipo de hardware: ";
    switch(b2todecimal(14)){
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
    c.imprimir_hexadecimal(16,17,1,0,"Tipo de protocolo: ", bytes);

    switch(b2todecimal(16)){
        case 2048:
          cout << "-> IPv4";
          break;

        case 2054:
          cout << "-> ARP";
          break;

        case 32821:
          cout << "-> RARP";
          break;
        
        case 34525:
          cout << "-> IPv6";
          break;
    }
    cout << endl;
    cout << "Longitud de la dirección hardware en bytes: ";
    cout <<btodecimal(18)<< endl;

    cout << "Longitud de la dirección protocolo en bytes: ";
    cout <<btodecimal(19)<< endl;
    
    cout << "Codigo de operacion: ";
    switch(b2todecimal(20)){
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
    
    c.imprimir_hexadecimal(22,27,1,1,"Direccion hardware emisor: ", bytes);
    IP_imprimir(28, "Direccion IP  del Emisor: ");

    c.imprimir_hexadecimal(32,37,1,1,"Direccion hardware receptor: ", bytes);
    IP_imprimir(38, "Direccion IP del receptor: ");
}

void Trama::RARP(){

    cout << "\nTipo de hardware: ";
    switch(b2todecimal(14)){
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

    switch(b2todecimal(16)){
        case 2048:
          cout << "-> IPv4";
          break;
        case 2054:
          cout << "-> ARP";
          break;
        case 32821:
          cout << "-> RARP";
          break;
        case 34525:
          cout << "--> IPv6";
          break;
    }
    cout << endl;
    cout << "Longitud de la dirección hardware en bytes: ";
    cout << btodecimal(18) << endl;

    cout << "Longitud de la dirección protocolo en bytes: ";
    cout << btodecimal(18) << endl;

    switch(b2todecimal(20)){
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
    
    c.imprimir_hexadecimal(22,27,1,1,"Direccion hardware emisor: ", bytes);
    IP_imprimir(28, "Direccion IP  del Emisor: ");

    c.imprimir_hexadecimal(32,37,1,1,"Direccion hardware receptor: ", bytes);
    IP_imprimir(38, "Direccion IP del receptor: ");

}

void Trama::imprimirResto(int algo){
    cout << "Datos: ";
    for (int i = algo; i < bytes.size(); i++){
        printf("%02X  ", bytes[i] & 0xFF);
        if((i%10) == 0 )
            cout << endl;
    }
}

void Trama::IPv6(){
    cout << endl;
    version_tamanio();
    clase_trafico();
    
    cout << "Etiqueda de flujo: ";
    auxS1 = c.convert(bytes[15], 0, 3) + c.convert(bytes[16], 0, 7) + c.convert(bytes[17], 0, 7);
    auxI1 = c.stringbinario_decimal(auxS1);
    cout << auxI1 << endl;

    cout << "Tamanio de Datos: ";
    auxS1 = c.convert(bytes[18], 0, 7) + c.convert(bytes[19], 0, 7);
    auxI1 = c.stringbinario_decimal(auxS1);
    cout << auxI1 << endl;

    protocolo(20);

    cout << "Limite de salto: " << btodecimal(21) << endl;

    cout << "Direccion de origen: ";
    int i = 22;
    int contador = 1;
    while(i < 38){
        printf("%02X", bytes[i] & 0xFF);
        
        if(contador%2 == 0)
            cout << ":";
        
        i++;
        contador++;
    }
    cout<<"\b \n";
    
    cout << "Direccion de destino: ";
    i = 38;
    contador = 1;
    while(i < 54){
        printf("%02X", bytes[i] & 0xFF);
        
        if(contador%2 == 0)
            cout << ":";
        
        i++;
        contador++;
    }

    switch(btodecimal(20)){
    case 6:
        cout << auxI1 << ". TCP" << endl;
        break;
    case 17:
        cout << auxI1 << ". UDP" << endl;
        break;
    case 58:
        cout << auxI1 << ". ICMP v6" << endl;
        cout << "=============ICMPv6==============" << endl;
        ICMPv6();
        break;
    case 118:
        cout << auxI1 << ". STP" << endl;
        break;
    case 121:
        cout << auxI1 << ". SMP" << endl;
        break;
    }
    
}

void Trama::clase_trafico(){
    auxS2 = c.convert(bytes[14], 0, 3);
    auxI1 = c.stringbinario_decimal(auxS2);

    cout << "Clase de trafico:" << endl;
    cout << "Prioridad: " << auxI1 << " ";

    switch(auxI1){
        case 0:
            cout << " ->  " << "De rutina";
            break;
        case 1:
            cout << " ->  " << "Prioritario";
            break;
        case 2:
            cout << " ->  "  << "Inmediato";
            break;
        case 3:
            cout << " ->  "  << "Relampago";
            break;
        case 4:
            cout << " ->  "  << "Invalidacion relampago";
            break;
        case 5:
            cout << " ->  "  << "Procesando llamada critica";
            break;
        case 6:
            cout << " ->  "  << "Control de trabajo de Internet";
            break;
        case 7:
            cout << " ->  "  << "Control de red";
    }

    cout << endl;
    auxS1 =c.convert(bytes[15],4,7);

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

void Trama::ICMPv6(){
  tipoMensajeInformativoICMPv6();
  checksum(56,"IPv6");
}

void Trama::tipoMensajeInformativoICMPv6() {
    switch (btodecimal(54))
    {
    case 1:
        cout << "1. Mensaje de destino inalcanzable" << endl;
        switch(btodecimal(55)){
            case 0:
              cout << "0. No existe ruta destino" << endl;
              break;
            case 1:
              cout << "1. Comunicacion con el destino administrativamente prohibida" << endl;
              break;
            case 2:
              cout << "2. No asignado" << endl;
              break;
            case 3:
              cout << "3. Direccion inalcanzable" << endl;
              break;
        }
        break;
    case 2:
        cout << "2. Mensaje de paquete demasiado grande" << endl;
        cout << "Descripcion del campo codigo: 0" << endl;
        break;
    case 3:
        cout << "3. Time Exceeded Message" << endl;
        switch(btodecimal(55)){
            case 0:
              cout<<"0. El limite de salto excedido"<<endl;
              break;
            case 1:
              cout<<"1. Tiempo de reensamble de fragmento excedido"<<endl;
              break;
        }
        break;
    case 4:
        cout << "4. Mesaje de problema de parametro" << endl;
        switch(btodecimal(55)){
          case 0:
            cout << "0. El campo del encabezado erroneo encontro" << endl;
            break;
          case 1:
            cout << "1. El tipo siguiete desconocido de la encabezado encontro" << endl;
            break;
          case 2 :
            cout << "2. Opcion desconocida del IPv6 encontrada" << endl;
            break;
        }
        break;
    case 128:
        cout << "128. Mensaje del pedido de eco" << endl;
        break;
    case 129:
        cout << "129. Mensaje de respuesta de eco" << endl;
        break;
    case 133:
        cout << "133. Mensaje de solicitud del router" << endl;
        break;
    case 134:
        cout << "134. Mensaje de anuncio del router" << endl;
        break;
    case 135:
        cout << "135. Mensaje de solucitud vecino" << endl;
        break;
    case 136:
        cout << "136. Mensaje de anuncio de vecino" << endl;
        break;
    case 137:
        cout << "137. Reoriente el mensaje " << endl;
        break;
  }
}

void Trama::TCP(int byte){ //38
    auxI1 = b2todecimal(byte); //39 y 40
    cout << "Puerto de origen: " << auxI1 << "\t" ;
    
	if(auxI1 < 1024){
    cout << "Puerto bien conocido. " << endl;
    switch(auxI1){
		case 20:
			cout << "20. servicio FTP" << endl;
			break;
		case 21:
			cout << "21. servicio FTP" << endl;
			break;
		case 22:
			cout << "22. servicio SSH" << endl;
			break;
		case 23:
			cout << "23. servicio TELNET" << endl;
			break;
		case 25:
			cout << "25. servicio SMTP" << endl;
			break;
		case 53:
			cout << "53. servicio DNS" << endl;
			break;
		case 67:
			cout << "67. servicio DHCP" << endl;
			break;
		case 68:
			cout << "68. servicio DHCP" << endl;
			break;
		case 69:
			cout << "69. servicio TFTP" << endl;
			break;
		case 80:
			cout << "80. servicio HTTP" << endl;
			break;
		case 110:
			cout << "143. servicio POP3" << endl;
			break;
		case 143:
			cout << "143. servicio IMAP" << endl;
			break;
		case 443:
			cout << "443. servicio HTTPS" << endl;
			break;
		case 993:
			cout << "993. servicio IMAP SSL" << endl;
			break;
		case 995:
			cout << "995. servicio POP SSL" << endl;
			break;
    }
	}
	else if (auxI1 > 1023 && auxI1 < 49152){
		cout << "Puertos registrados​" << endl;
	}
	else if (auxI1 > 49152 && auxI1 < 65535){
		cout << "Puertos dinamicos o privados​" << endl;
	}
  

  auxI1 = b2todecimal(byte+2);
  cout << "Puerto de destino: " << auxI1 << "\t";
  if(auxI1 < 1024){
    cout << "Puerto bien conocido. " << endl;
    switch(auxI1){
		case 20:
			cout << "20. servicio FTP" << endl;
			break;
		case 21:
			cout << "21. servicio FTP" << endl;
			break;
		case 22:
			cout << "22. servicio SSH" << endl;
			break;
		case 23:
			cout << "23. servicio TELNET" << endl;
			break;
		case 25:
			cout << "25. servicio SMTP" << endl;
			break;
		case 53:
			cout << "53. servicio DNS" << endl;
			break;
		case 67:
			cout << "67. servicio DHCP" << endl;
			break;
		case 68:
			cout << "68. servicio DHCP" << endl;
			break;
		case 69:
			cout << "69. servicio TFTP" << endl;
			break;
		case 80:
			cout << "80. servicio HTTP" << endl;
			break;
		case 110:
			cout << "143. servicio POP3" << endl;
			break;
		case 143:
			cout << "143. servicio IMAP" << endl;
			break;
		case 443:
			cout << "443. servicio HTTPS" << endl;
			break;
		case 993:
			cout << "993. servicio IMAP SSL" << endl;
			break;
		case 995:
			cout << "995. servicio POP SSL" << endl;
			break;
    }
	}
	else if (auxI1 > 1023 && auxI1 < 49152){
		cout << "Puertos registrados​" << endl;
	}
	else if (auxI1 > 49152 && auxI1 < 65535){
		cout << "Puertos dinamicos o privados​" << endl;
	}

    
	auxS1 = c.convert(bytes[byte+4], 0, 7) + c.convert(bytes[byte+5], 0, 7) + c.convert(bytes[byte+6], 0, 7) + c.convert(bytes[byte+7], 0, 7);
	auxI1 = c.stringbinario_decimal(auxS1);
	cout << "Numero de Secuencia: " << auxI1 << endl;
    
	auxS1 = c.convert(bytes[byte+8], 0, 7) + c.convert(bytes[byte+9], 0, 7) + c.convert(bytes[byte+10], 0, 7) + c.convert(bytes[byte+11], 0, 7);
	auxI1 = c.stringbinario_decimal(auxS1);
	cout << "Numero de acuse de recibo: " << auxI1 << endl;

	c.imprimir_hexadecimal(byte+11, byte+11, 0, 0, "Longitud de cabecera: ", bytes);
  
	cout  << endl <<  "Reservado: "<< c.convert(bytes[byte+11], 1, 3) << endl;

	auxS1 = c.convert(bytes[byte+11],0,1);
	cout << "flags:" << endl;
	auxI1 = auxS1[0] - '0';
	auxS2 = (auxI1 == 1) ? "NS -> 1":"NS -> 0 ";
	cout << auxS2 << "\t";
    
    auxS1 = c.convert(bytes[byte+12],0,7);
    auxI1 = auxS1[0] - '0';
    auxS2 = (auxI1 == 1) ? "CWR -> 1" : "CWR -> 0";
	cout << auxS2 << "\t";
    auxI1 = auxS1[1] - '0';
    auxS2 = (auxI1 == 1) ? "ECE -> 1" : "ECE -> 0";
	cout << auxS2 << endl;
    auxI1 = auxS1[2] - '0';
    auxS2 = (auxI1 == 1) ? "URG -> 1" : "URG -> 0";
	cout << auxS2 << "\t";
    auxI1 = auxS1[3] - '0';
    auxS2 = (auxI1 == 1) ? "ACK -> 1" : "ACK -> 0";
	cout << auxS2 << "\t";
    auxI1 = auxS1[4] - '0';
    auxS2 = (auxI1 == 1) ? "PSH -> 1" : "PSH -> 0";
	cout << auxS2 << endl;
    auxI1 = auxS1[5] - '0';
    auxS2 = (auxI1 == 1) ? "RST -> 1" : "RST -> 0";
	cout << auxS2 << "\t";
    auxI1 = auxS1[6] - '0';
    auxS2 = (auxI1 == 1) ? "SYN -> 1" : "SYN -> 0";
	cout << auxS2 << "\t";
    auxI1 = auxS1[7] - '0';
    auxS2 = (auxI1 == 1) ? "FIN -> 1" : "FIN -> 0";
	cout << auxS2 << endl;
	      
    cout << "Tamanio de ventana: " << b2todecimal(byte+13) << endl;
    c.imprimir_hexadecimal(byte+15, byte+16, 0, 0, "Suma de verificacion: ", bytes);
	cout << endl;
    cout << "Puntero urgente: " << b2todecimal(byte+17) << endl;
}