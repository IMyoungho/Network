TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt
LIBS += -lpcap
SOURCES += main.cpp \
    parse.cpp \
    cal_checksum.cpp

HEADERS += \
    parse.h \
    parse_packet.h \
    cal_checksum.h
