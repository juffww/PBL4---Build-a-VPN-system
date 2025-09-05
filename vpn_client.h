#ifndef VPN_CLIENT_H
#define VPN_CLIENT_H

#include <QObject>
#include <QTcpSocket>
#include <QTimer>
#include <QString>

class VPNClient : public QObject
{
    Q_OBJECT

public:
    explicit VPNClient(QObject *parent = nullptr);
    ~VPNClient();

    void connectToServer(const QString& host, int port, const QString& username, const QString& password);
    void disconnectFromServer();
    bool isConnected() const;

    // VPN specific methods
    void requestVPNIP();
    void requestStatus();
    QString getCurrentVPNIP() const { return assignedVpnIP; }

signals:
    void connected();
    void disconnected();
    void error(const QString& errorMessage);
    void authenticationResult(bool success, const QString& message);
    void messageReceived(const QString& message);
    void vpnIPAssigned(const QString& vpnIP);
    void statusReceived(const QString& status);

private slots:
    void onConnected();
    void onDisconnected();
    void onReadyRead();
    void onError(QAbstractSocket::SocketError socketError);
    void sendPing();

private:
    void authenticate(const QString& username, const QString& password);
    void sendMessage(const QString& message);
    void parseServerMessage(const QString& message);

    QTcpSocket *socket;
    QTimer *pingTimer;

    bool authenticated;
    QString serverHost;
    int serverPort;
    QString assignedVpnIP;
    QString serverIP;
};

#endif // VPN_CLIENT_H
