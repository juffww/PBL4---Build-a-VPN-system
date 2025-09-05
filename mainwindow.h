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
    QString getCurrentLocalIP();

    // UI Components
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

    QSystemTrayIcon *systemTrayIcon;
    QTimer *statsTimer;
    QTimer *ipCheckTimer;

    // Network
    QNetworkAccessManager *networkManager;
    QNetworkReply *currentReply;

    // VPN
    VPNClient *vpnClient;
    bool isConnected;
    bool isHideMessageShown;

    // Connection time tracking - THÊM MỚI
    QTime connectionStartTime;
    bool connectionTimeStarted;

    quint64 totalDownload;
    quint64 totalUpload;

    QString currentRealIP;
    QString currentVpnIP;
    QString currentPublicIP;
};

#endif // MAINWINDOW_H
