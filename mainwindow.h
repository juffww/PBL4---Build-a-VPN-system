#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QComboBox>
#include <QTextEdit>
#include <QProgressBar>
#include <QTimer>
#include <QTime>  // Thêm để xử lý thời gian
#include <QSystemTrayIcon>
#include <QCloseEvent>
#include <QGroupBox>
#include <QNetworkAccessManager>
#include <QNetworkReply>

class QRadioButton;
class VPNClient;
class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:
    void connectToVPN();
    void disconnectFromVPN();
    void clearLog();
    void showAbout();
    void toggleWindow();
    void updateStats();
    void updateRealIP();
    void checkCurrentIP();
    void onPublicIPReceived();
    bool parseServerAddress(const QString& serverInput, QString& host, int& port);
    void onRegionChanged();
private:
    void setupUI();
    void setupSystemTray();
    void setupTimer();
    void setupVPNClientConnections();
    void updateConnectionStatus();
    void loadSettings();
    void saveSettings();
    void closeEvent(QCloseEvent *event) override;
    void getPublicIP();
    bool isServerReachable(const QString& host);
    QString getCurrentLocalIP();

    QLabel *statusLabel;
    QLabel *realIPLabel;
    QLabel *vpnIPLabel;
    QLabel *publicIPLabel;
    QLabel *downloadLabel;
    QLabel *uploadLabel;
    QLabel *connectionTimeLabel;

    QLineEdit *serverEdit;
    QLineEdit *usernameEdit;
    QLineEdit *passwordEdit;
    QComboBox *protocolCombo;

    QPushButton *connectButton;
    QTextEdit *logTextEdit;
    QProgressBar *progressBar;

    QGroupBox *regionGroup; //thêm radio button
    QRadioButton *usRadioButton;
    QRadioButton *sgRadioButton;
    QRadioButton *ukRadioButton;

    QSystemTrayIcon *systemTrayIcon;
    QTimer *statsTimer;
    QTimer *ipCheckTimer;

    QNetworkAccessManager *networkManager;
    QNetworkReply *currentReply;

    VPNClient *vpnClient;
    bool isConnected;
    bool isHideMessageShown;

    QTime connectionStartTime;
    bool connectionTimeStarted;

    quint64 totalDownload;
    quint64 totalUpload;

    QString currentRealIP;
    QString currentVpnIP;
    QString currentPublicIP;

    QPushButton* trafficButton;
    QTimer* webTrafficTimer;
    bool trafficRunning;
};

#endif
