#ifndef ETHERNET_H_INCLUDED
#define ETHERNET_H_INCLUDED

class Ethernet {
    private:
        int destinationAddress1;
        int surfaceAddress1;
        int destinationAddress2;
        int surfaceAddress2;
        int destinationAddress3;
        int surfaceAddress3;
        int destinationAddress4;
        int surfaceAddress4;
        int destinationAddress5;
        int surfaceAddress5;
        int destinationAddress6;
        int surfaceAddress6;
        int type1;
        int type2;

    public:
        int getDestinationAddress1();
        int getSurfaceAddress1();
        int getDestinationAddress2();
        int getSurfaceAddress2();
        int getDestinationAddress3();
        int getSurfaceAddress3();
        int getDestinationAddress4();
        int getSurfaceAddress4();
        int getDestinationAddress5();
        int getSurfaceAddress5();
        int getDestinationAddress6();
        int getSurfaceAddress6();
        int getType1();
        int getType2();

        void setDestinationAddress1(const int da1);
        void setSurfaceAddress1(const int sa1);
        void setDestinationAddress2(const int da2);
        void setSurfaceAddress2(const int sa2);
        void setDestinationAddress3(const int da3);
        void setSurfaceAddress3(const int sa3);
        void setDestinationAddress4(const int da4);
        void setSurfaceAddress4(const int sa4);
        void setDestinationAddress5(const int da5);
        void setSurfaceAddress5(const int sa5);
        void setDestinationAddress6(const int da6);
        void setSurfaceAddress6(const int sa6);
        void setType1(const int t1);
        void setType2(const int t2);
    };

int Ethernet::getDestinationAddress1()
{
    return destinationAddress1;
}

int Ethernet::getSurfaceAddress1()
{
    return surfaceAddress1;
}

int Ethernet::getDestinationAddress2()
{
    return destinationAddress2;
}

int Ethernet::getSurfaceAddress2()
{
    return surfaceAddress2;
}

int Ethernet::getDestinationAddress3()
{
    return destinationAddress3;
}

int Ethernet::getSurfaceAddress3()
{
    return surfaceAddress3;
}

int Ethernet::getDestinationAddress4()
{
    return destinationAddress4;
}

int Ethernet::getSurfaceAddress4()
{
    return surfaceAddress4;
}

int Ethernet::getDestinationAddress5()
{
    return destinationAddress5;
}

int Ethernet::getSurfaceAddress5()
{
    return surfaceAddress5;
}

int Ethernet::getDestinationAddress6()
{
    return destinationAddress6;
}

int Ethernet::getSurfaceAddress6()
{
    return surfaceAddress6;
}

void Ethernet::setDestinationAddress1(const int da1)
{
    destinationAddress1 = da1;
}

void Ethernet::setSurfaceAddress1(const int sa1)
{
    surfaceAddress1 = sa1;
}

void Ethernet::setDestinationAddress2(const int da2)
{
    destinationAddress2 = da2;
}

void Ethernet::setSurfaceAddress2(const int sa2)
{
    surfaceAddress2 = sa2;
}

void Ethernet::setDestinationAddress3(const int da3)
{
    destinationAddress3 = da3;
}

void Ethernet::setSurfaceAddress3(const int sa3)
{
    surfaceAddress3 = sa3;
}

void Ethernet::setDestinationAddress4(const int da4)
{
    destinationAddress4 = da4;
}

void Ethernet::setSurfaceAddress4(const int sa4)
{
    surfaceAddress4 = sa4;
}

void Ethernet::setDestinationAddress5(const int da5)
{
    destinationAddress5 = da5;
}

void Ethernet::setSurfaceAddress5(const int sa5)
{
    surfaceAddress5 = sa5;
}

void Ethernet::setDestinationAddress6(const int da6)
{
    destinationAddress6 = da6;
}

void Ethernet::setSurfaceAddress6(const int sa6)
{
    surfaceAddress6 = sa6;
}

int Ethernet::getType1()
{
    return type1;
}

int Ethernet::getType2()
{
    return type2;
}

void Ethernet::setType1(const int t1)
{
    type1 = t1;
}

void Ethernet::setType2(const int t2)
{
    type2 = t2;
}

#endif // ETHERNET_H_INCLUDED
