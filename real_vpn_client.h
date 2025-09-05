#ifndef REAL_VPN_CLIENT_H
#define REAL_VPN_CLIENT_H

#include <QtCore>
#include <QTcpSocket>
#include <QTimer>
#include <QThread>
#include <QMutex>
#include <QDebug>

// System headers for TUN interface
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <cstring>
#include <cerrno>

class RealVPNClient : public QObject
{
    Q_OBJECT

private:
    QTcpSocket* controlSocket;
    QTimer* pingTimer;
    QTimer* statsTimer;

    // TUN interface
    int tunFd;
    QString tunInterfaceName;
    QString vpnIP;
    QString serverIP;
    bool tunCreated;

    // Threading for packet handling
    QThread* packetThread;
    bool isRunning;
    QMutex statsMutex;

    // Statistics
    quint64 bytesReceived;
    quint64 bytesSent;
    quint64 packetsReceived;
    quint64 packetsSent;

    // Connection state
    bool isAuthenticated;
    QString username;
    QString password;

public:
    explicit RealVPNClient(QObject *parent = nullptr);
    ~RealVPNClient();

    // Connection methods
    void connectToServer(const QString& host, int port, const QString& user, const QString& pass);
    void disconnectFromServer();
    bool isConnected() const;

    void sendControlMessage(const QString& message);

    // TUN interface methods
    bool createTunInterface();
    bool configureTunInterface(const QString& ip, const QString& gateway);
    void closeTunInterface();

    // Statistics
    quint64 getBytesReceived() const { QMutexLocker lock(&statsMutex); return bytesReceived; }
    quint64 getBytesSent() const { QMutexLocker lock(&statsMutex); return bytesSent; }
    quint64 getPacketsReceived() const { QMutexLocker lock(&statsMutex); return packetsReceived; }
    quint64 getPacketsSent() const { QMutexLocker lock(&statsMutex); return packetsSent; }

    // Check if we have required permissions
    static bool checkCapabilities();
    static QString getCapabilityError();

private slots:
    void onControlConnected();
    void onControlDisconnected();
    void onControlReadyRead();
    void onControlError(QAbstractSocket::SocketError error);
    void sendPing();
    void updateStats();

private:
    // Packet processing
    void startPacketProcessing();
    void stopPacketProcessing();
    void processPackets(); // Runs in separate thread

    // Protocol methods
    void handleServerMessage(const QString& message);
    void authenticate();

    // System commands
    bool executeCommand(const QString& command);
    bool setRoutes();
    bool restoreRoutes();

    // Helper methods
    void handleIncomingPacket(const QByteArray& packetData);
    void writePacketToTun(const QByteArray& packet);

signals:
    void connected();
    void disconnected();
    void authenticated(bool success, const QString& message);
    void vpnIPAssigned(const QString& ip);
    void error(const QString& errorMsg);
    void statsUpdated(quint64 bytesRx, quint64 bytesTx, quint64 packetsRx, quint64 packetsTx);
};

#endif // REAL_VPN_CLIENT_H
