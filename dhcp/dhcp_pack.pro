TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt
LIBS += -lpcap
SOURCES += main.cpp \
    parse.cpp

HEADERS += \
    parse.h \
    dhcp_header.h \
    detect_parsing_packet.h \
    conver_char_to_binary.h \
    send_dhcp_offer.h \
    checksum.h
