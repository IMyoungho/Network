TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt
LIBS += -lpcap
SOURCES += \
        main.cpp \
    parse.cpp \
    come_packet.cpp \
    convert_type.cpp

HEADERS += \
    parse.h \
    come_packet.h \
    convert_type.h
