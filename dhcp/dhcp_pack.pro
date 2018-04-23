TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt
LIBS += -lpcap
LIBS += -lpthread
SOURCES += main.cpp \
    parse.cpp \
    convert_char_to_binary.cpp \
    send_packet.cpp

HEADERS += \
    parse.h \
    dhcp_header.h \
    detect_parsing_packet.h \
    checksum.h \
    convert_char_to_binary.h \
    send_packet.h
