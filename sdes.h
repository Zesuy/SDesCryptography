#ifndef SDES_H
#define SDES_H

#include <QMainWindow>
#include <QWidget>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGroupBox>
#include <QLabel>
#include <QPlainTextEdit>
#include <QLineEdit>
#include <QPushButton>
#include <QRadioButton>
#include <QButtonGroup>
#include <QTabWidget>
#include <QProgressBar>
#include <QCheckBox>
#include <QThread>
#include <QMessageBox>
#include <QDateTime>
#include <QDebug>
#include <vector>
#include <string>
#include <bitset>
#include <sstream>
#include <iomanip>
#include <thread>
#include <future>

// 暴力破解线程类
class BruteforceThread : public QThread
{
    Q_OBJECT
public:
    explicit BruteforceThread(QObject *parent = nullptr,
                              const std::string& plaintext = "",
                              const std::string& ciphertext = "",
                              bool useMultiThreading = false,
                              bool isBinaryMode = false);

    void run() override;

signals:
    void progressUpdated(int progress);
    void keyFound(const std::string& key, double timeElapsed);
    void allKeysFound(const std::vector<std::string>& keys, double timeElapsed);

private:
    std::string m_plaintext;
    std::string m_ciphertext;
    bool m_useMultiThreading;
    bool m_isBinaryMode;

    // S-DES算法函数
    char permute10(const std::string& key, const std::vector<int>& pbox);
    char permute8(const std::string& key, const std::vector<int>& pbox);
    std::string leftShift(const std::string& key, int shift);
    std::string generateKey1(const std::string& key);
    std::string generateKey2(const std::string& key);
    char initialPermutation(char data);
    char finalPermutation(char data);
    char expansionPermutation(char data);
    char sBoxSubstitution(char data);
    char p4Permutation(char data);
    char fFunction(char data, const std::string& key);
    char switchFunction(char data);
    char encryptChar(char plaintext, const std::string& key);
    char decryptChar(char ciphertext, const std::string& key);
    std::string encryptString(const std::string& plaintext, const std::string& key);
    std::string decryptString(const std::string& ciphertext, const std::string& key);

    // 工具函数
    std::string stringToHex(const std::string& input);
    bool isHexString(const std::string& str);
    std::string hexToString(const std::string& hex);
    std::string binaryToString(const std::string& binary);
    std::string stringToBinary(const std::string& str);
    bool isValidBinaryInput(const std::string& input);

    // 置换盒定义
    const std::vector<int> P10 = {3,5,2,7,4,10,1,9,8,6};
    const std::vector<int> P8 = {6,3,7,4,8,5,10,9};
    const std::vector<int> IP = {2,6,3,1,4,8,5,7};
    const std::vector<int> IP_inv = {4,1,3,5,7,2,8,6};
    const std::vector<int> EP = {4,1,2,3,2,3,4,1};
    const std::vector<int> P4 = {2,4,3,1};

    // S盒定义
    const std::vector<std::vector<int>> SBOX1 = {
        {1,0,3,2},
        {3,2,1,0},
        {0,2,1,3},
        {3,1,0,2}
    };

    const std::vector<std::vector<int>> SBOX2 = {
        {0,1,2,3},
        {2,3,1,0},
        {3,0,1,2},
        {2,1,0,3}
    };
};

class SDes : public QMainWindow
{
    Q_OBJECT

public:
    SDes(QWidget *parent = nullptr);
    ~SDes();

private slots:
    void on_encryptButton_clicked();
    void on_decryptButton_clicked();
    void on_bruteforceButton_clicked();
    void on_clearButton_clicked();
    void on_testButton_clicked();
    void on_keyFound(const std::string& key, double timeElapsed);
    void on_allKeysFound(const std::vector<std::string>& keys, double timeElapsed);
    void on_progressUpdated(int progress);

private:
    // UI组件
    QTabWidget *tabWidget;

    // 加解密标签页组件
    QWidget *encryptionTab;
    QRadioButton *asciiRadio;
    QRadioButton *binaryRadio;
    QRadioButton *hexDisplayRadio;
    QRadioButton *rawDisplayRadio;
    QPlainTextEdit *plaintextEdit;
    QLineEdit *keyEdit;
    QPlainTextEdit *ciphertextEdit;
    QLineEdit *binaryOutput;
    QPushButton *encryptButton;
    QPushButton *decryptButton;
    QPushButton *clearButton;
    QPushButton *testButton;

    // 暴力破解标签页组件
    QWidget *bruteforceTab;
    QRadioButton *bruteAsciiRadio;
    QRadioButton *bruteBinaryRadio;
    QPlainTextEdit *brutePlaintextEdit;
    QPlainTextEdit *bruteCiphertextEdit;
    QCheckBox *multithreadCheckbox;
    QPushButton *bruteforceButton;
    QProgressBar *bruteforceProgress;
    QPlainTextEdit *bruteResultEdit;

    BruteforceThread *m_bruteforceThread;

    void setupUI();
    void debugEncryption(char plaintext, const std::string& key);
    void testBruteforce();

    // S-DES核心算法函数
    char permute10(const std::string& key, const std::vector<int>& pbox);
    char permute8(const std::string& key, const std::vector<int>& pbox);
    std::string leftShift(const std::string& key, int shift);
    std::string generateKey1(const std::string& key);
    std::string generateKey2(const std::string& key);
    char initialPermutation(char data);
    char finalPermutation(char data);
    char expansionPermutation(char data);
    char sBoxSubstitution(char data);
    char p4Permutation(char data);
    char fFunction(char data, const std::string& key);
    char switchFunction(char data);
    char encryptChar(char plaintext, const std::string& key);
    char decryptChar(char ciphertext, const std::string& key);
    std::string encryptString(const std::string& plaintext, const std::string& key);
    std::string decryptString(const std::string& ciphertext, const std::string& key);

    // 工具函数
    std::string charToBinaryString(char c);
    char binaryStringToChar(const std::string& binary);
    std::string stringToBinary(const std::string& str);
    std::string binaryToString(const std::string& binary);
    std::string stringToHex(const std::string& input);
    std::string hexToString(const std::string& hex);
    bool isHexString(const std::string& str);
    bool isValidBinaryKey(const std::string& key);
    bool isValidBinaryInput(const std::string& input);
    void testAlgorithm();

    // 置换盒定义
    const std::vector<int> P10 = {3,5,2,7,4,10,1,9,8,6};
    const std::vector<int> P8 = {6,3,7,4,8,5,10,9};
    const std::vector<int> IP = {2,6,3,1,4,8,5,7};
    const std::vector<int> IP_inv = {4,1,3,5,7,2,8,6};
    const std::vector<int> EP = {4,1,2,3,2,3,4,1};
    const std::vector<int> P4 = {2,4,3,1};

    // S盒定义
    const std::vector<std::vector<int>> SBOX1 = {
        {1,0,3,2},
        {3,2,1,0},
        {0,2,1,3},
        {3,1,0,2}
    };

    const std::vector<std::vector<int>> SBOX2 = {
        {0,1,2,3},
        {2,3,1,0},
        {3,0,1,2},
        {2,1,0,3}
    };
};

#endif // SDES_H
