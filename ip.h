#ifndef IP_H_INCLUDED
#define IP_H_INCLUDED

using namespace std;

class Ip {
    private:
        string ipversion;
        int version1;
        int version2;
        int length1;
        int length2;
        int identity1;
        int identity2;
        int flags;
        int displacement;
        int lifeTime;
        int protocol;
        int checkSum1;
        int checkSum2;
        int destinationAddress1;
        int surfaceAddress1;
        int destinationAddress2;
        int surfaceAddress2;
        int destinationAddress3;
        int surfaceAddress3;
        int destinationAddress4;
        int surfaceAddress4;

    public:
        Ip();
        string getStringVersion();
        int getVersion1();
        int getVersion2();
        int getLength1();
        int getLength2();
        int getIdentity1();
        int getIdentity2();
        int getFlags();
        int getDisplacement();
        int getLifeTime();
        int getProtocol();
        int getCheckSum1();
        int getCheckSum2();
        int getDestinationAddress1();
        int getSurfaceAddress1();
        int getDestinationAddress2();
        int getSurfaceAddress2();
        int getDestinationAddress3();
        int getSurfaceAddress3();
        int getDestinationAddress4();
        int getSurfaceAddress4();

        void setVersion1(const int v1);
        void setVersion2(const int v2);
        void setLength1(const int l1);
        void setLength2(const int l2);
        void setIdentity1(const int i1);
        void setIdentity2(const int i2);
        void setFlags(const int f);
        void setDisplacement(const int d);
        void setLifeTime(const int lt);
        void setProtocol(const int p);
        void setCheckSum1(const int c1);
        void setCheckSum2(const int c2);
        void setDestinationAddress1(const int d1);
        void setSurfaceAddress1(const int s1);
        void setDestinationAddress2(const int d2);
        void setSurfaceAddress2(const int s2);
        void setDestinationAddress3(const int d3);
        void setSurfaceAddress3(const int s3);
        void setDestinationAddress4(const int d4);
        void setSurfaceAddress4(const int s4);
    };

Ip::Ip() {
    ipversion = "IPV4";
    }

string Ip::getStringVersion(){
    return ipversion;
}

int Ip::getVersion1()
{
    return version1;
}

int Ip::getVersion2()
{
    return version2;
}

int Ip::getLength1()
{
    return length1;
}

int Ip::getLength2()
{
    return length2;
}

int Ip::getIdentity1()
{
    return identity1;
}

int Ip::getIdentity2()
{
    return identity2;
}

int Ip::getFlags()
{
    return flags;
}

int Ip::getDisplacement()
{
    return displacement;
}

int Ip::getLifeTime()
{
    return lifeTime;
}

int Ip::getProtocol()
{
    return protocol;
}

int Ip::getCheckSum1()
{
    return checkSum1;
}

int Ip::getCheckSum2()
{
    return checkSum2;
}

int Ip::getDestinationAddress1()
{
    return destinationAddress1;
}

int Ip::getSurfaceAddress1()
{
    return surfaceAddress1;
}

int Ip::getDestinationAddress2()
{
    return destinationAddress2;
}

int Ip::getSurfaceAddress2()
{
    return surfaceAddress2;
}

int Ip::getDestinationAddress3()
{
    return destinationAddress3;
}

int Ip::getSurfaceAddress3()
{
    return surfaceAddress3;
}

int Ip::getDestinationAddress4()
{
    return destinationAddress4;
}

int Ip::getSurfaceAddress4()
{
    return surfaceAddress4;
}

void Ip::setVersion1(const int v1)
{
    version1 = v1;
}

void Ip::setVersion2(const int v2)
{
    version2 = v2;
}

void Ip::setLength1(const int l1)
{
    length1 = l1;
}

void Ip::setLength2(const int l2)
{
    length2 = l2;
}

void Ip::setIdentity1(const int i1)
{
    identity1 = i1;
}

void Ip::setIdentity2(const int i2)
{
    identity2 = i2;
}

void Ip::setFlags(const int f)
{
    flags = f;
}

void Ip::setDisplacement(const int d)
{
    displacement = d;
}

void Ip::setLifeTime(const int lt)
{
    lifeTime = lt;
}

void Ip::setProtocol(const int p)
{
    protocol = p;
}

void Ip::setCheckSum1(const int c1)
{
    checkSum1 = c1;
}

void Ip::setCheckSum2(const int c2)
{
    checkSum2 = c2;
}

void Ip::setDestinationAddress1(const int d1)
{
    destinationAddress1 = d1;
}

void Ip::setSurfaceAddress1(const int s1)
{
    surfaceAddress1 = s1;
}

void Ip::setDestinationAddress2(const int d2)
{
    destinationAddress2 = d2;
}

void Ip::setSurfaceAddress2(const int s2)
{
    surfaceAddress2 = s2;
}

void Ip::setDestinationAddress3(const int d3)
{
    destinationAddress3 = d3;
}

void Ip::setSurfaceAddress3(const int s3)
{
    surfaceAddress3 = s3;
}

void Ip::setDestinationAddress4(const int d4)
{
    destinationAddress4 = d4;
}

void Ip::setSurfaceAddress4(const int s4)
{
    surfaceAddress4 = s4;
}

#endif // IP_H_INCLUDED
