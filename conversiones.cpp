#include "conversiones.h"

using namespace std;

//Funcion para convertir un caracter a bits (y lo entrega en forma de string)
string Conversiones::convert(char n,int minimo,int maximo) {

    string arreglo;

        for(int i= maximo ; i>= minimo ;i--)
            arreglo +=  (n & (1 << i) ? '1' : '0');

    return arreglo;
}

//Convierte la cadena de la funcion convert
//de binario a decimal
long Conversiones::stringbinario_decimal(string car){

  long potencia[32] = {2147483648,1073741824,536870912,268435456,134217728,67108864,33554432,16777216,8388608,4194304,2097152,1048576,524288,262144,131072,65536,32768,16384,8192,4096,2048,1024,512,256,128,64,32,16,8,4,2,1};
  auxI1  = 0;
  int potenciaPos = 32 - car.size();

  for(int i= 0 ; i< car.size() ; i++){
          auxI2 =  car[i] - '0';
          auxI1 += auxI2 * potencia[potenciaPos];
          potenciaPos++;
  }
  return auxI1;
}

void Conversiones::imprimir_hexadecimal(int inicio, int fin,int separacion,int saltoLinea, string campo, vector<unsigned char> bytes){
    cout<<campo ;

    for(int i = inicio; i<= fin; i++){
        if(separacion == 1)
            printf("%02X:", bytes[i] & 0xFF);
        else
            printf("%02X ", bytes[i] & 0xFF);
    }

    if(saltoLinea == 1)
      cout<<"\b \n";
    else
      cout<<"\b";
    
}

