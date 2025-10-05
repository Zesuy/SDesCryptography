#include "sdes.h"

// BruteforceThread 实现
BruteforceThread::BruteforceThread(QObject *parent,
                                   const std::string& plaintext,
                                   const std::string& ciphertext,
                                   bool useMultiThreading,
                                   bool isBinaryMode)
    : QThread(parent), m_plaintext(plaintext), m_ciphertext(ciphertext),
    m_useMultiThreading(useMultiThreading), m_isBinaryMode(isBinaryMode)
{
}

// BruteforceThread的工具函数实现
std::string BruteforceThread::binaryToString(const std::string& binary) {
    std::string str;
    for (size_t i = 0; i < binary.length(); i += 8) {
        if (i + 8 > binary.length()) break;
        std::string byte = binary.substr(i, 8);
        char c = static_cast<char>(std::bitset<8>(byte).to_ulong());
        str += c;
    }
    return str;
}

std::string BruteforceThread::stringToBinary(const std::string& str) {
    std::string binary;
    for (char c : str) {
        binary += std::bitset<8>(c).to_string();
    }
    return binary;
}

bool BruteforceThread::isValidBinaryInput(const std::string& input) {
    if (input.length() % 8 != 0) return false;
    for (char c : input) {
        if (c != '0' && c != '1') return false;
    }
    return true;
}

// BruteforceThread的算法函数实现
char BruteforceThread::permute10(const std::string& key, const std::vector<int>& pbox) {
    std::bitset<10> result;
    for (size_t i = 0; i < pbox.size(); i++) {
        result[9 - i] = key[10 - pbox[i]] == '1';
    }
    return static_cast<char>(result.to_ulong());
}

char BruteforceThread::permute8(const std::string& key, const std::vector<int>& pbox) {
    std::bitset<8> result;
    for (size_t i = 0; i < pbox.size(); i++) {
        result[7 - i] = key[10 - pbox[i]] == '1';
    }
    return static_cast<char>(result.to_ulong());
}

std::string BruteforceThread::leftShift(const std::string& key, int shift) {
    std::string left = key.substr(0, 5);
    std::string right = key.substr(5, 5);

    left = left.substr(shift) + left.substr(0, shift);
    right = right.substr(shift) + right.substr(0, shift);

    return left + right;
}

std::string BruteforceThread::generateKey1(const std::string& key) {
    std::string shifted = leftShift(key, 1);
    std::bitset<8> key1(permute8(shifted, P8));
    return key1.to_string();
}

std::string BruteforceThread::generateKey2(const std::string& key) {
    std::string shiftedOnce = leftShift(key, 1);
    std::string shiftedTwice = leftShift(shiftedOnce, 2);
    std::bitset<8> key2(permute8(shiftedTwice, P8));
    return key2.to_string();
}

char BruteforceThread::initialPermutation(char data) {
    std::bitset<8> bits(data);
    std::bitset<8> result;
    for (size_t i = 0; i < IP.size(); i++) {
        result[7 - i] = bits[8 - IP[i]];
    }
    return static_cast<char>(result.to_ulong());
}

char BruteforceThread::finalPermutation(char data) {
    std::bitset<8> bits(data);
    std::bitset<8> result;
    for (size_t i = 0; i < IP_inv.size(); i++) {
        result[7 - i] = bits[8 - IP_inv[i]];
    }
    return static_cast<char>(result.to_ulong());
}

char BruteforceThread::expansionPermutation(char data) {
    std::bitset<4> bits(data & 0x0F);
    std::bitset<8> result;
    for (size_t i = 0; i < EP.size(); i++) {
        result[7 - i] = bits[4 - EP[i]];
    }
    return static_cast<char>(result.to_ulong());
}

char BruteforceThread::sBoxSubstitution(char data) {
    std::bitset<8> bits(data);

    // 修正S盒查找逻辑
    // 左4位（S盒1）
    int row1 = (bits[7] << 1 | bits[4]) & 0x03;
    int col1 = (bits[6] << 1 | bits[5]) & 0x03;
    int s1 = SBOX1[row1][col1];

    // 右4位（S盒2）
    int row2 = (bits[3] << 1 | bits[0]) & 0x03;
    int col2 = (bits[2] << 1 | bits[1]) & 0x03;
    int s2 = SBOX2[row2][col2];

    std::bitset<4> result((s1 << 2) | s2);
    return static_cast<char>(result.to_ulong());
}

char BruteforceThread::p4Permutation(char data) {
    std::bitset<4> bits(data);
    std::bitset<4> result;
    for (size_t i = 0; i < P4.size(); i++) {
        result[3 - i] = bits[4 - P4[i]];
    }
    return static_cast<char>(result.to_ulong());
}

char BruteforceThread::fFunction(char data, const std::string& key) {
    char expanded = expansionPermutation(data);
    std::bitset<8> expandedBits(expanded);
    std::bitset<8> keyBits(std::stoi(key, nullptr, 2));

    std::bitset<8> xored = expandedBits ^ keyBits;
    char substituted = sBoxSubstitution(static_cast<char>(xored.to_ulong()));

    return p4Permutation(substituted);
}

char BruteforceThread::switchFunction(char data) {
    std::bitset<8> bits(data);
    std::bitset<4> left(bits.to_ulong() >> 4);
    std::bitset<4> right(bits.to_ulong() & 0x0F);

    std::bitset<8> result((right.to_ulong() << 4) | left.to_ulong());
    return static_cast<char>(result.to_ulong());
}

char BruteforceThread::encryptChar(char plaintext, const std::string& key) {
    std::string key1 = generateKey1(key);
    std::string key2 = generateKey2(key);

    char ip = initialPermutation(plaintext);

    std::bitset<8> ipBits(ip);
    std::bitset<4> left1(ipBits.to_ulong() >> 4);
    std::bitset<4> right1(ipBits.to_ulong() & 0x0F);

    char f1 = fFunction(static_cast<char>(right1.to_ulong()), key1);
    std::bitset<4> f1Bits(f1);
    std::bitset<4> newRight1(left1.to_ulong() ^ f1Bits.to_ulong());

    std::bitset<8> afterSwap((newRight1.to_ulong() << 4) | right1.to_ulong());
    char swapped = switchFunction(static_cast<char>(afterSwap.to_ulong()));

    std::bitset<8> swapBits(swapped);
    std::bitset<4> left2(swapBits.to_ulong() >> 4);
    std::bitset<4> right2(swapBits.to_ulong() & 0x0F);

    char f2 = fFunction(static_cast<char>(right2.to_ulong()), key2);
    std::bitset<4> f2Bits(f2);
    std::bitset<4> newRight2(left2.to_ulong() ^ f2Bits.to_ulong());

    std::bitset<8> beforeFinal((newRight2.to_ulong() << 4) | right2.to_ulong());

    return finalPermutation(static_cast<char>(beforeFinal.to_ulong()));
}

char BruteforceThread::decryptChar(char ciphertext, const std::string& key) {
    std::string key1 = generateKey1(key);
    std::string key2 = generateKey2(key);

    char ip = initialPermutation(ciphertext);

    std::bitset<8> ipBits(ip);
    std::bitset<4> left1(ipBits.to_ulong() >> 4);
    std::bitset<4> right1(ipBits.to_ulong() & 0x0F);

    // 解密时先使用K2，然后使用K1
    char f1 = fFunction(static_cast<char>(right1.to_ulong()), key2);
    std::bitset<4> f1Bits(f1);
    std::bitset<4> newRight1(left1.to_ulong() ^ f1Bits.to_ulong());

    std::bitset<8> afterSwap((newRight1.to_ulong() << 4) | right1.to_ulong());
    char swapped = switchFunction(static_cast<char>(afterSwap.to_ulong()));

    std::bitset<8> swapBits(swapped);
    std::bitset<4> left2(swapBits.to_ulong() >> 4);
    std::bitset<4> right2(swapBits.to_ulong() & 0x0F);

    char f2 = fFunction(static_cast<char>(right2.to_ulong()), key1);
    std::bitset<4> f2Bits(f2);
    std::bitset<4> newRight2(left2.to_ulong() ^ f2Bits.to_ulong());

    std::bitset<8> beforeFinal((newRight2.to_ulong() << 4) | right2.to_ulong());

    return finalPermutation(static_cast<char>(beforeFinal.to_ulong()));
}

std::string BruteforceThread::encryptString(const std::string& plaintext, const std::string& key) {
    std::string ciphertext;
    for (char c : plaintext) {
        ciphertext += encryptChar(c, key);
    }
    return ciphertext;
}

std::string BruteforceThread::decryptString(const std::string& ciphertext, const std::string& key) {
    std::string plaintext;
    for (char c : ciphertext) {
        plaintext += decryptChar(c, key);
    }
    return plaintext;
}

void BruteforceThread::run() {
    QDateTime startTime = QDateTime::currentDateTime();
    std::vector<std::string> foundKeys;

    // 根据输入模式处理明密文
    std::string actualPlaintext = m_plaintext;
    std::string actualCiphertext = m_ciphertext;

    if (m_isBinaryMode) {
        // 二进制模式：将二进制字符串转换为普通字符串
        if (!isValidBinaryInput(m_plaintext)) {
            emit allKeysFound({}, 0);
            return;
        }
        if (!isValidBinaryInput(m_ciphertext)) {
            emit allKeysFound({}, 0);
            return;
        }
        actualPlaintext = binaryToString(m_plaintext);
        actualCiphertext = binaryToString(m_ciphertext);
    }

    auto bruteforceRange = [&](int start, int end) {
        for (int i = start; i < end; i++) {
            std::bitset<10> keyBits(i);
            std::string key = keyBits.to_string();

            std::string encrypted = encryptString(actualPlaintext, key);

            // 根据模式比较结果
            bool match = false;
            if (m_isBinaryMode) {
                // 二进制模式：将加密结果转换为二进制再比较
                std::string encryptedBinary = stringToBinary(encrypted);
                match = (encryptedBinary == m_ciphertext);
            } else {
                // ASCII模式：直接比较
                match = (encrypted == actualCiphertext);
            }

            if (match) {
                foundKeys.push_back(key);
            }

            if (i % 100 == 0) {
                int progress = static_cast<double>(i - start) / (end - start) * 100;
                emit progressUpdated(progress);
            }
        }
    };

    if (m_useMultiThreading) {
        unsigned int numThreads = std::thread::hardware_concurrency();
        std::vector<std::future<void>> futures;
        int range = 1024 / numThreads;

        for (unsigned int i = 0; i < numThreads; i++) {
            int start = i * range;
            int end = (i == numThreads - 1) ? 1024 : (i + 1) * range;
            futures.push_back(std::async(std::launch::async, bruteforceRange, start, end));
        }

        for (auto& future : futures) {
            future.wait();
        }
    } else {
        bruteforceRange(0, 1024);
    }

    QDateTime endTime = QDateTime::currentDateTime();
    double timeElapsed = startTime.msecsTo(endTime) / 1000.0;

    emit allKeysFound(foundKeys, timeElapsed);
}

// SDes 类实现
SDes::SDes(QWidget *parent)
    : QMainWindow(parent)
    , m_bruteforceThread(nullptr)
{
    setupUI();
    setWindowTitle(QStringLiteral("S-DES加密解密工具"));
    resize(800, 600);

    // 测试算法
    testAlgorithm();
}

SDes::~SDes()
{
    if (m_bruteforceThread && m_bruteforceThread->isRunning()) {
        m_bruteforceThread->terminate();
        m_bruteforceThread->wait();
    }
}

void SDes::setupUI() {
    // 创建主选项卡
    tabWidget = new QTabWidget(this);
    setCentralWidget(tabWidget);

    // 创建加解密标签页
    encryptionTab = new QWidget();
    tabWidget->addTab(encryptionTab, QStringLiteral("加解密"));

    // 加解密标签页布局
    QVBoxLayout *mainLayout = new QVBoxLayout(encryptionTab);

    // 输入模式选择
    QGroupBox *modeGroup = new QGroupBox(QStringLiteral("输入模式"));
    QHBoxLayout *modeLayout = new QHBoxLayout();
    asciiRadio = new QRadioButton(QStringLiteral("ASCII文本"));
    binaryRadio = new QRadioButton(QStringLiteral("二进制"));
    asciiRadio->setChecked(true);
    modeLayout->addWidget(asciiRadio);
    modeLayout->addWidget(binaryRadio);
    modeLayout->addStretch();
    modeGroup->setLayout(modeLayout);
    mainLayout->addWidget(modeGroup);

    // 显示模式选择
    QGroupBox *displayGroup = new QGroupBox(QStringLiteral("显示模式"));
    QHBoxLayout *displayLayout = new QHBoxLayout();
    hexDisplayRadio = new QRadioButton(QStringLiteral("十六进制"));
    rawDisplayRadio = new QRadioButton(QStringLiteral("原始字节"));
    hexDisplayRadio->setChecked(true);
    displayLayout->addWidget(hexDisplayRadio);
    displayLayout->addWidget(rawDisplayRadio);
    displayLayout->addStretch();
    displayGroup->setLayout(displayLayout);
    mainLayout->addWidget(displayGroup);

    // 加解密区域
    QGroupBox *cryptoGroup = new QGroupBox(QStringLiteral("加密/解密"));
    QVBoxLayout *cryptoLayout = new QVBoxLayout();

    // 明文输入
    QHBoxLayout *plainLayout = new QHBoxLayout();
    plainLayout->addWidget(new QLabel(QStringLiteral("明文:")));
    plaintextEdit = new QPlainTextEdit();
    plaintextEdit->setMaximumHeight(80);
    plainLayout->addWidget(plaintextEdit);
    cryptoLayout->addLayout(plainLayout);

    // 密钥输入
    QHBoxLayout *keyLayout = new QHBoxLayout();
    keyLayout->addWidget(new QLabel(QStringLiteral("密钥(10位二进制):")));
    keyEdit = new QLineEdit();
    keyEdit->setMaxLength(10);
    keyEdit->setPlaceholderText(QStringLiteral("例如: 1010000010"));
    keyLayout->addWidget(keyEdit);
    cryptoLayout->addLayout(keyLayout);

    // 密文输出
    QHBoxLayout *cipherLayout = new QHBoxLayout();
    cipherLayout->addWidget(new QLabel(QStringLiteral("密文:")));
    ciphertextEdit = new QPlainTextEdit();
    ciphertextEdit->setMaximumHeight(80);
    cipherLayout->addWidget(ciphertextEdit);
    cryptoLayout->addLayout(cipherLayout);

    // 二进制输出
    QHBoxLayout *binaryLayout = new QHBoxLayout();
    binaryLayout->addWidget(new QLabel(QStringLiteral("二进制输出:")));
    binaryOutput = new QLineEdit();
    binaryLayout->addWidget(binaryOutput);
    cryptoLayout->addLayout(binaryLayout);

    // 按钮
    QHBoxLayout *buttonLayout = new QHBoxLayout();
    encryptButton = new QPushButton(QStringLiteral("加密"));
    decryptButton = new QPushButton(QStringLiteral("解密"));
    clearButton = new QPushButton(QStringLiteral("清空"));
    testButton = new QPushButton(QStringLiteral("测试算法"));
    buttonLayout->addWidget(encryptButton);
    buttonLayout->addWidget(decryptButton);
    buttonLayout->addWidget(clearButton);
    buttonLayout->addWidget(testButton);
    cryptoLayout->addLayout(buttonLayout);

    cryptoGroup->setLayout(cryptoLayout);
    mainLayout->addWidget(cryptoGroup);

    // 创建暴力破解标签页
    bruteforceTab = new QWidget();
    tabWidget->addTab(bruteforceTab, QStringLiteral("暴力破解"));

    QVBoxLayout *bruteLayout = new QVBoxLayout(bruteforceTab);

    QGroupBox *bruteGroup = new QGroupBox(QStringLiteral("暴力破解设置"));
    QVBoxLayout *bruteInnerLayout = new QVBoxLayout();

    // 暴力破解输入模式选择
    QGroupBox *bruteModeGroup = new QGroupBox(QStringLiteral("输入模式"));
    QHBoxLayout *bruteModeLayout = new QHBoxLayout();
    bruteAsciiRadio = new QRadioButton(QStringLiteral("ASCII文本"));
    bruteBinaryRadio = new QRadioButton(QStringLiteral("二进制"));
    bruteAsciiRadio->setChecked(true);
    bruteModeLayout->addWidget(bruteAsciiRadio);
    bruteModeLayout->addWidget(bruteBinaryRadio);
    bruteModeLayout->addStretch();
    bruteModeGroup->setLayout(bruteModeLayout);
    bruteInnerLayout->addWidget(bruteModeGroup);

    // 明密文对输入
    QHBoxLayout *brutePlainLayout = new QHBoxLayout();
    brutePlainLayout->addWidget(new QLabel(QStringLiteral("已知明文:")));
    brutePlaintextEdit = new QPlainTextEdit();
    brutePlaintextEdit->setMaximumHeight(60);
    brutePlainLayout->addWidget(brutePlaintextEdit);
    bruteInnerLayout->addLayout(brutePlainLayout);

    QHBoxLayout *bruteCipherLayout = new QHBoxLayout();
    bruteCipherLayout->addWidget(new QLabel(QStringLiteral("已知密文:")));
    bruteCiphertextEdit = new QPlainTextEdit();
    bruteCiphertextEdit->setMaximumHeight(60);
    bruteCipherLayout->addWidget(bruteCiphertextEdit);
    bruteInnerLayout->addLayout(bruteCipherLayout);

    // 多线程选项
    multithreadCheckbox = new QCheckBox(QStringLiteral("使用多线程加速"));
    bruteInnerLayout->addWidget(multithreadCheckbox);

    // 破解按钮和进度条
    QHBoxLayout *bruteButtonLayout = new QHBoxLayout();
    bruteforceButton = new QPushButton(QStringLiteral("开始暴力破解"));
    bruteforceProgress = new QProgressBar();
    bruteforceProgress->setValue(0);
    bruteButtonLayout->addWidget(bruteforceButton);
    bruteButtonLayout->addWidget(bruteforceProgress);
    bruteInnerLayout->addLayout(bruteButtonLayout);

    // 结果显示
    bruteInnerLayout->addWidget(new QLabel(QStringLiteral("破解结果:")));
    bruteResultEdit = new QPlainTextEdit();
    bruteResultEdit->setReadOnly(true);
    bruteInnerLayout->addWidget(bruteResultEdit);

    bruteGroup->setLayout(bruteInnerLayout);
    bruteLayout->addWidget(bruteGroup);

    // 连接信号槽
    connect(encryptButton, &QPushButton::clicked, this, &SDes::on_encryptButton_clicked);
    connect(decryptButton, &QPushButton::clicked, this, &SDes::on_decryptButton_clicked);
    connect(clearButton, &QPushButton::clicked, this, &SDes::on_clearButton_clicked);
    connect(testButton, &QPushButton::clicked, this, &SDes::on_testButton_clicked);
    connect(bruteforceButton, &QPushButton::clicked, this, &SDes::on_bruteforceButton_clicked);
}

// 调试函数
void SDes::debugEncryption(char plaintext, const std::string& key) {
    qDebug() << "=== 调试加密过程 ===";
    qDebug() << "明文:" << QString::number((unsigned char)plaintext, 2).rightJustified(8, '0');
    qDebug() << "密钥:" << QString::fromStdString(key);

    std::string key1 = generateKey1(key);
    std::string key2 = generateKey2(key);
    qDebug() << "K1:" << QString::fromStdString(key1);
    qDebug() << "K2:" << QString::fromStdString(key2);

    char ip = initialPermutation(plaintext);
    qDebug() << "IP后:" << QString::number((unsigned char)ip, 2).rightJustified(8, '0');

    std::bitset<8> ipBits(ip);
    std::bitset<4> left1(ipBits.to_ulong() >> 4);
    std::bitset<4> right1(ipBits.to_ulong() & 0x0F);
    qDebug() << "左半部分:" << QString::number(left1.to_ulong(), 2).rightJustified(4, '0');
    qDebug() << "右半部分:" << QString::number(right1.to_ulong(), 2).rightJustified(4, '0');

    char f1 = fFunction(static_cast<char>(right1.to_ulong()), key1);
    std::bitset<4> f1Bits(f1);
    std::bitset<4> newRight1(left1.to_ulong() ^ f1Bits.to_ulong());
    qDebug() << "f1结果:" << QString::number(f1Bits.to_ulong(), 2).rightJustified(4, '0');
    qDebug() << "新的右半部分:" << QString::number(newRight1.to_ulong(), 2).rightJustified(4, '0');

    std::bitset<8> afterSwap((newRight1.to_ulong() << 4) | right1.to_ulong());
    char swapped = switchFunction(static_cast<char>(afterSwap.to_ulong()));
    qDebug() << "交换后:" << QString::number((unsigned char)swapped, 2).rightJustified(8, '0');

    std::bitset<8> swapBits(swapped);
    std::bitset<4> left2(swapBits.to_ulong() >> 4);
    std::bitset<4> right2(swapBits.to_ulong() & 0x0F);
    qDebug() << "第二轮左半部分:" << QString::number(left2.to_ulong(), 2).rightJustified(4, '0');
    qDebug() << "第二轮右半部分:" << QString::number(right2.to_ulong(), 2).rightJustified(4, '0');

    char f2 = fFunction(static_cast<char>(right2.to_ulong()), key2);
    std::bitset<4> f2Bits(f2);
    std::bitset<4> newRight2(left2.to_ulong() ^ f2Bits.to_ulong());
    qDebug() << "f2结果:" << QString::number(f2Bits.to_ulong(), 2).rightJustified(4, '0');
    qDebug() << "第二轮新的右半部分:" << QString::number(newRight2.to_ulong(), 2).rightJustified(4, '0');

    std::bitset<8> beforeFinal((newRight2.to_ulong() << 4) | right2.to_ulong());
    qDebug() << "最终置换前:" << QString::number(beforeFinal.to_ulong(), 2).rightJustified(8, '0');

    char result = finalPermutation(static_cast<char>(beforeFinal.to_ulong()));
    qDebug() << "最终密文:" << QString::number((unsigned char)result, 2).rightJustified(8, '0');
    qDebug() << "=== 调试结束 ===";
}

// 工具函数
std::string SDes::charToBinaryString(char c) {
    return std::bitset<8>(c).to_string();
}

char SDes::binaryStringToChar(const std::string& binary) {
    return static_cast<char>(std::bitset<8>(binary).to_ulong());
}

std::string SDes::stringToBinary(const std::string& str) {
    std::string binary;
    for (char c : str) {
        binary += charToBinaryString(c);
    }
    return binary;
}

std::string SDes::binaryToString(const std::string& binary) {
    std::string str;
    for (size_t i = 0; i < binary.length(); i += 8) {
        str += binaryStringToChar(binary.substr(i, 8));
    }
    return str;
}

std::string SDes::stringToHex(const std::string& input) {
    std::string hexStr;
    const char hexChars[] = "0123456789ABCDEF";

    for (unsigned char c : input) {
        hexStr += hexChars[(c >> 4) & 0x0F];
        hexStr += hexChars[c & 0x0F];
        hexStr += " "; // 添加空格便于阅读
    }

    // 移除最后一个空格
    if (!hexStr.empty()) {
        hexStr.pop_back();
    }

    return hexStr;
}

std::string SDes::hexToString(const std::string& hex) {
    std::string result;
    std::string cleanHex;

    // 移除空格
    for (char c : hex) {
        if (c != ' ') cleanHex += c;
    }

    for (size_t i = 0; i < cleanHex.length(); i += 2) {
        if (i + 1 >= cleanHex.length()) break;

        std::string byteStr = cleanHex.substr(i, 2);
        char byte = static_cast<char>(std::stoi(byteStr, nullptr, 16));
        result += byte;
    }

    return result;
}

bool SDes::isHexString(const std::string& str) {
    std::string cleanStr;
    for (char c : str) {
        if (c != ' ') cleanStr += c;
    }

    if (cleanStr.empty()) return false;

    for (char c : cleanStr) {
        if (!std::isxdigit(c)) {
            return false;
        }
    }
    return true;
}

bool SDes::isValidBinaryKey(const std::string& key) {
    if (key.length() != 10) return false;
    for (char c : key) {
        if (c != '0' && c != '1') return false;
    }
    return true;
}

bool SDes::isValidBinaryInput(const std::string& input) {
    if (input.length() % 8 != 0) return false;
    for (char c : input) {
        if (c != '0' && c != '1') return false;
    }
    return true;
}

// S-DES算法函数实现
char SDes::permute10(const std::string& key, const std::vector<int>& pbox) {
    std::bitset<10> result;
    for (size_t i = 0; i < pbox.size(); i++) {
        result[9 - i] = key[10 - pbox[i]] == '1';
    }
    return static_cast<char>(result.to_ulong());
}

char SDes::permute8(const std::string& key, const std::vector<int>& pbox) {
    std::bitset<8> result;
    for (size_t i = 0; i < pbox.size(); i++) {
        result[7 - i] = key[10 - pbox[i]] == '1';
    }
    return static_cast<char>(result.to_ulong());
}

std::string SDes::leftShift(const std::string& key, int shift) {
    std::string left = key.substr(0, 5);
    std::string right = key.substr(5, 5);

    left = left.substr(shift) + left.substr(0, shift);
    right = right.substr(shift) + right.substr(0, shift);

    return left + right;
}

std::string SDes::generateKey1(const std::string& key) {
    std::string shifted = leftShift(key, 1);
    std::bitset<8> key1(permute8(shifted, P8));
    return key1.to_string();
}

std::string SDes::generateKey2(const std::string& key) {
    std::string shiftedOnce = leftShift(key, 1);
    std::string shiftedTwice = leftShift(shiftedOnce, 2);
    std::bitset<8> key2(permute8(shiftedTwice, P8));
    return key2.to_string();
}

char SDes::initialPermutation(char data) {
    std::bitset<8> bits(data);
    std::bitset<8> result;
    for (size_t i = 0; i < IP.size(); i++) {
        result[7 - i] = bits[8 - IP[i]];
    }
    return static_cast<char>(result.to_ulong());
}

char SDes::finalPermutation(char data) {
    std::bitset<8> bits(data);
    std::bitset<8> result;
    for (size_t i = 0; i < IP_inv.size(); i++) {
        result[7 - i] = bits[8 - IP_inv[i]];
    }
    return static_cast<char>(result.to_ulong());
}

char SDes::expansionPermutation(char data) {
    std::bitset<4> bits(data & 0x0F);
    std::bitset<8> result;
    for (size_t i = 0; i < EP.size(); i++) {
        result[7 - i] = bits[4 - EP[i]];
    }
    return static_cast<char>(result.to_ulong());
}

char SDes::sBoxSubstitution(char data) {
    std::bitset<8> bits(data);

    // 修正S盒查找逻辑
    // 左4位（S盒1）
    int row1 = (bits[7] << 1 | bits[4]) & 0x03;
    int col1 = (bits[6] << 1 | bits[5]) & 0x03;
    int s1 = SBOX1[row1][col1];

    // 右4位（S盒2）
    int row2 = (bits[3] << 1 | bits[0]) & 0x03;
    int col2 = (bits[2] << 1 | bits[1]) & 0x03;
    int s2 = SBOX2[row2][col2];

    std::bitset<4> result((s1 << 2) | s2);
    return static_cast<char>(result.to_ulong());
}

char SDes::p4Permutation(char data) {
    std::bitset<4> bits(data);
    std::bitset<4> result;
    for (size_t i = 0; i < P4.size(); i++) {
        result[3 - i] = bits[4 - P4[i]];
    }
    return static_cast<char>(result.to_ulong());
}

char SDes::fFunction(char data, const std::string& key) {
    char expanded = expansionPermutation(data);
    std::bitset<8> expandedBits(expanded);
    std::bitset<8> keyBits(std::stoi(key, nullptr, 2));

    std::bitset<8> xored = expandedBits ^ keyBits;
    char substituted = sBoxSubstitution(static_cast<char>(xored.to_ulong()));

    return p4Permutation(substituted);
}

char SDes::switchFunction(char data) {
    std::bitset<8> bits(data);
    std::bitset<4> left(bits.to_ulong() >> 4);
    std::bitset<4> right(bits.to_ulong() & 0x0F);

    std::bitset<8> result((right.to_ulong() << 4) | left.to_ulong());
    return static_cast<char>(result.to_ulong());
}

char SDes::encryptChar(char plaintext, const std::string& key) {
    std::string key1 = generateKey1(key);
    std::string key2 = generateKey2(key);

    char ip = initialPermutation(plaintext);

    std::bitset<8> ipBits(ip);
    std::bitset<4> left1(ipBits.to_ulong() >> 4);
    std::bitset<4> right1(ipBits.to_ulong() & 0x0F);

    char f1 = fFunction(static_cast<char>(right1.to_ulong()), key1);
    std::bitset<4> f1Bits(f1);
    std::bitset<4> newRight1(left1.to_ulong() ^ f1Bits.to_ulong());

    std::bitset<8> afterSwap((newRight1.to_ulong() << 4) | right1.to_ulong());
    char swapped = switchFunction(static_cast<char>(afterSwap.to_ulong()));

    std::bitset<8> swapBits(swapped);
    std::bitset<4> left2(swapBits.to_ulong() >> 4);
    std::bitset<4> right2(swapBits.to_ulong() & 0x0F);

    char f2 = fFunction(static_cast<char>(right2.to_ulong()), key2);
    std::bitset<4> f2Bits(f2);
    std::bitset<4> newRight2(left2.to_ulong() ^ f2Bits.to_ulong());

    std::bitset<8> beforeFinal((newRight2.to_ulong() << 4) | right2.to_ulong());

    return finalPermutation(static_cast<char>(beforeFinal.to_ulong()));
}

char SDes::decryptChar(char ciphertext, const std::string& key) {
    std::string key1 = generateKey1(key);
    std::string key2 = generateKey2(key);

    char ip = initialPermutation(ciphertext);

    std::bitset<8> ipBits(ip);
    std::bitset<4> left1(ipBits.to_ulong() >> 4);
    std::bitset<4> right1(ipBits.to_ulong() & 0x0F);

    // 解密时先使用K2，然后使用K1
    char f1 = fFunction(static_cast<char>(right1.to_ulong()), key2);
    std::bitset<4> f1Bits(f1);
    std::bitset<4> newRight1(left1.to_ulong() ^ f1Bits.to_ulong());

    std::bitset<8> afterSwap((newRight1.to_ulong() << 4) | right1.to_ulong());
    char swapped = switchFunction(static_cast<char>(afterSwap.to_ulong()));

    std::bitset<8> swapBits(swapped);
    std::bitset<4> left2(swapBits.to_ulong() >> 4);
    std::bitset<4> right2(swapBits.to_ulong() & 0x0F);

    char f2 = fFunction(static_cast<char>(right2.to_ulong()), key1);
    std::bitset<4> f2Bits(f2);
    std::bitset<4> newRight2(left2.to_ulong() ^ f2Bits.to_ulong());

    std::bitset<8> beforeFinal((newRight2.to_ulong() << 4) | right2.to_ulong());

    return finalPermutation(static_cast<char>(beforeFinal.to_ulong()));
}

std::string SDes::encryptString(const std::string& plaintext, const std::string& key) {
    std::string ciphertext;
    for (char c : plaintext) {
        ciphertext += encryptChar(c, key);
    }
    return ciphertext;
}

std::string SDes::decryptString(const std::string& ciphertext, const std::string& key) {
    std::string plaintext;
    for (char c : ciphertext) {
        plaintext += decryptChar(c, key);
    }
    return plaintext;
}

void SDes::testAlgorithm() {
    qDebug() << "=== S-DES算法测试 ===";

    // 测试用例1: 标准测试
    char testChar = 'A';
    std::string testKey = "1010000010";

    char encrypted = encryptChar(testChar, testKey);
    char decrypted = decryptChar(encrypted, testKey);

    qDebug() << "测试字符: 'A' (0x41)";
    qDebug() << "加密结果:" << QString::number((unsigned char)encrypted, 16) << "解密结果:" << decrypted;
    qDebug() << "测试" << (testChar == decrypted ? "通过" : "失败");

    // 测试用例2: 全1测试
    char allOnes = static_cast<char>(0xFF); // 11111111
    std::string allOnesKey = "1111111111";
    char encryptedOnes = encryptChar(allOnes, allOnesKey);
    char decryptedOnes = decryptChar(encryptedOnes, allOnesKey);

    qDebug() << "全1测试 - 明文: 11111111, 密钥: 1111111111";
    qDebug() << "加密结果:" << QString::number((unsigned char)encryptedOnes, 2).rightJustified(8, '0');
    qDebug() << "解密结果:" << QString::number((unsigned char)decryptedOnes, 2).rightJustified(8, '0');
    qDebug() << "测试" << (allOnes == decryptedOnes ? "通过" : "失败");

    // 调试全1加密过程
    debugEncryption(allOnes, allOnesKey);

    // 测试用例3: 字符串
    std::string testStr = "Hello";
    std::string encryptedStr = encryptString(testStr, testKey);
    std::string decryptedStr = decryptString(encryptedStr, testKey);

    qDebug() << "测试字符串: 'Hello'";
    qDebug() << "解密结果:" << QString::fromStdString(decryptedStr);
    qDebug() << "测试" << (testStr == decryptedStr ? "通过" : "失败");

    // 测试用例4: 修复的解密问题测试
    qDebug() << "=== 修复解密问题测试 ===";
    char testChar2 = static_cast<char>(0x81); // 10000001
    std::string testKey2 = "0000000000";
    char encrypted2 = encryptChar(testChar2, testKey2);
    char decrypted2 = decryptChar(encrypted2, testKey2);

    qDebug() << "测试字符: 10000001, 密钥: 0000000000";
    qDebug() << "加密结果:" << QString::number((unsigned char)encrypted2, 2).rightJustified(8, '0');
    qDebug() << "解密结果:" << QString::number((unsigned char)decrypted2, 2).rightJustified(8, '0');
    qDebug() << "测试" << (testChar2 == decrypted2 ? "通过" : "失败");
}

// 槽函数实现
void SDes::on_encryptButton_clicked() {
    std::string plaintext = plaintextEdit->toPlainText().toStdString();
    std::string key = keyEdit->text().toStdString();

    if (!isValidBinaryKey(key)) {
        QMessageBox::warning(this, QStringLiteral("错误"), QStringLiteral("密钥必须是10位二进制数！"));
        return;
    }

    // 临时调试：测试全1情况
    if (plaintext == "11111111" && key == "1111111111") {
        char testChar = static_cast<char>(0xFF);
        std::string testKey = "1111111111";
        debugEncryption(testChar, testKey);
    }

    if (asciiRadio->isChecked()) {
        // ASCII模式
        std::string ciphertext = encryptString(plaintext, key);

        // 根据显示模式选择输出格式
        if (hexDisplayRadio->isChecked()) {
            // 十六进制显示
            std::string hexCiphertext = stringToHex(ciphertext);
            ciphertextEdit->setPlainText(QString::fromStdString(hexCiphertext));
        } else {
            // 原始字节显示
            ciphertextEdit->setPlainText(QString::fromStdString(ciphertext));
        }

        // 显示二进制
        std::string binary = stringToBinary(ciphertext);
        binaryOutput->setText(QString::fromStdString(binary));
    } else {
        // 二进制模式
        if (!isValidBinaryInput(plaintext)) {
            QMessageBox::warning(this, QStringLiteral("错误"), QStringLiteral("明文必须是8位的倍数二进制数！"));
            return;
        }

        std::string asciiPlaintext = binaryToString(plaintext);
        std::string ciphertext = encryptString(asciiPlaintext, key);
        std::string binaryCiphertext = stringToBinary(ciphertext);

        ciphertextEdit->setPlainText(QString::fromStdString(binaryCiphertext));
        binaryOutput->setText(QString::fromStdString(binaryCiphertext));
    }
}

void SDes::on_decryptButton_clicked() {
    std::string ciphertext = ciphertextEdit->toPlainText().toStdString();
    std::string key = keyEdit->text().toStdString();

    if (!isValidBinaryKey(key)) {
        QMessageBox::warning(this, QStringLiteral("错误"), QStringLiteral("密钥必须是10位二进制数！"));
        return;
    }

    if (asciiRadio->isChecked()) {
        // ASCII模式 - 支持十六进制输入
        std::string decryptedText;

        // 检查输入是否是十六进制格式
        if (isHexString(ciphertext)) {
            std::string binaryData = hexToString(ciphertext);
            decryptedText = decryptString(binaryData, key);
        } else {
            // 普通ASCII输入
            decryptedText = decryptString(ciphertext, key);
        }

        plaintextEdit->setPlainText(QString::fromStdString(decryptedText));

        // 在二进制输出中显示解密结果的二进制形式
        std::string binary = stringToBinary(decryptedText);
        binaryOutput->setText(QString::fromStdString(binary));
    } else {
        // 二进制模式 - 直接输出二进制结果
        if (!isValidBinaryInput(ciphertext)) {
            QMessageBox::warning(this, QStringLiteral("错误"), QStringLiteral("密文必须是8位的倍数二进制数！"));
            return;
        }

        std::string asciiCiphertext = binaryToString(ciphertext);
        std::string plaintext = decryptString(asciiCiphertext, key);

        // 将解密结果转换为二进制字符串显示
        std::string binaryPlaintext = stringToBinary(plaintext);
        plaintextEdit->setPlainText(QString::fromStdString(binaryPlaintext));

        // 在二进制输出中也显示二进制形式
        binaryOutput->setText(QString::fromStdString(binaryPlaintext));
    }
}

void SDes::on_bruteforceButton_clicked() {
    std::string plaintext = brutePlaintextEdit->toPlainText().toStdString();
    std::string ciphertext = bruteCiphertextEdit->toPlainText().toStdString();

    if (plaintext.empty() || ciphertext.empty()) {
        QMessageBox::warning(this, QStringLiteral("错误"), QStringLiteral("请提供明密文对！"));
        return;
    }

    bool useMultiThreading = multithreadCheckbox->isChecked();
    bool isBinaryMode = bruteBinaryRadio->isChecked();

    // 在二进制模式下验证输入格式
    if (isBinaryMode) {
        if (!isValidBinaryInput(plaintext)) {
            QMessageBox::warning(this, QStringLiteral("错误"), QStringLiteral("已知明文必须是8位的倍数二进制数！"));
            return;
        }
        if (!isValidBinaryInput(ciphertext)) {
            QMessageBox::warning(this, QStringLiteral("错误"), QStringLiteral("已知密文必须是8位的倍数二进制数！"));
            return;
        }
    }

    if (m_bruteforceThread && m_bruteforceThread->isRunning()) {
        m_bruteforceThread->terminate();
        m_bruteforceThread->wait();
    }

    m_bruteforceThread = new BruteforceThread(this, plaintext, ciphertext, useMultiThreading, isBinaryMode);
    connect(m_bruteforceThread, &BruteforceThread::keyFound, this, &SDes::on_keyFound);
    connect(m_bruteforceThread, &BruteforceThread::allKeysFound, this, &SDes::on_allKeysFound);
    connect(m_bruteforceThread, &BruteforceThread::progressUpdated, this, &SDes::on_progressUpdated);

    bruteforceButton->setEnabled(false);
    bruteforceProgress->setValue(0);
    bruteResultEdit->clear();

    m_bruteforceThread->start();
}

void SDes::on_clearButton_clicked() {
    plaintextEdit->clear();
    ciphertextEdit->clear();
    keyEdit->clear();
    binaryOutput->clear();
    brutePlaintextEdit->clear();
    bruteCiphertextEdit->clear();
    bruteResultEdit->clear();
    bruteforceProgress->setValue(0);
}

void SDes::on_testButton_clicked() {
    testAlgorithm();
    QMessageBox::information(this, QStringLiteral("测试完成"),
                             QStringLiteral("算法测试已完成，请查看调试输出。"));
}

void SDes::on_keyFound(const std::string& key, double timeElapsed) {
    QString result = QStringLiteral("找到密钥: %1\n耗时: %2 秒")
                         .arg(QString::fromStdString(key))
                         .arg(timeElapsed, 0, 'f', 3);
    bruteResultEdit->setPlainText(result);
}

void SDes::on_allKeysFound(const std::vector<std::string>& keys, double timeElapsed) {
    bruteforceButton->setEnabled(true);
    bruteforceProgress->setValue(100);

    QString result;
    if (keys.empty()) {
        result = QStringLiteral("未找到匹配的密钥\n耗时: %1 秒").arg(timeElapsed, 0, 'f', 3);
    } else {
        result = QStringLiteral("找到 %1 个匹配的密钥:\n").arg(keys.size());
        for (const auto& key : keys) {
            result += QString::fromStdString(key) + "\n";
        }
        result += QStringLiteral("\n耗时: %1 秒").arg(timeElapsed, 0, 'f', 3);

        if (keys.size() > 1) {
            result += QStringLiteral("\n\n注意：存在多个密钥可以加密得到相同密文！");
        }
    }

    bruteResultEdit->setPlainText(result);
}

void SDes::on_progressUpdated(int progress) {
    bruteforceProgress->setValue(progress);
}
