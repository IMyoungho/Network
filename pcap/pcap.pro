TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt
LIBS += -lpcap
SOURCES += main.cpp \
    parse.cpp \
    come_on_packet.cpp
    

HEADERS += \
    parse.h \
    come_on_packet.h
