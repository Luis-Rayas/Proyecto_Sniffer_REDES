#ifndef TCP_H_INCLUDED
#define TCP_H_INCLUDED

class Tcp {
    private:
        int port;
        int protocol;

    public:
        int getPort();
        void setPort(const int p);
        int getProtocol();
        void setProtocol(const int p);
    };

int Tcp::getPort() {
    return port;
    }

void Tcp::setPort(const int p) {
    port = p;
    }

int Tcp::getProtocol() {
    return protocol;
    }

void Tcp::setProtocol(const int p) {
    protocol = p;
    }

#endif // TCP_H_INCLUDED
