#ifndef EXTRACTSESSIONWORKER_H
#define EXTRACTSESSIONWORKER_H

#include <QObject>
#include <iostream>
#include <string>

using namespace std;

class extractSessionWorker : public QObject
{
    Q_OBJECT
public:
    extractSessionWorker(string fName);

signals:

};

#endif // EXTRACTSESSIONWORKER_H
