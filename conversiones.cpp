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
//de binario a decimal :3
int Conversiones::binario_decimal(string car){

  short potencia[8] = {128,64,32,16,8,4,2,1};
  auxI1  = 0;
  int potenciaPos = 8 - car.size();

  for(int i= 0 ; i< car.size() ; i++){
          auxI2 =  car[i] - '0';
          auxI1 += auxI2 * potencia[potenciaPos];
          potenciaPos++;
  }
  return auxI1;
}
