TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt
LIBS += -lpcap
LIBS += -lpthread
SOURCES += \
        main.cpp \
    parse.cpp \
    come_on_packet.cpp \
    convert_type.cpp

HEADERS += \
    parse.h \
    come_on_packet.h \
    ieee80211.h \
    convert_type.h
