#include "sdes.h"
#include <QApplication>
#include <QFont>

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);

    // 设置中文字体
    QFont font;
    font.setFamily("Microsoft YaHei");  // 微软雅黑
    a.setFont(font);

    SDes w;
    w.show();
    return a.exec();
}
