TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt
LIBS += /usr/lib/x86_64-linux-gnu/libnetfilter_queue.so -ltins
SOURCES += main.cpp
