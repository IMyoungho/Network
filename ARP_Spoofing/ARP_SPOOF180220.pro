TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt
LIBS += -lpcap
LIBS += -lpthread
SOURCES += main.cpp \
    parse_data.cpp \
    char_to_binary.cpp \
    make_request_packet.cpp \
    send_packet.cpp \
    parse_data_in_linux.cpp \
    get_target_data.cpp \
    get_sender_data.cpp \
    make_send_reply_packet.cpp \
    relay_normal_packet.cpp

HEADERS += \
    parse_data.h \
    parse_data_in_linux.h \
    char_to_binary.h \
    send_packet.h \
    make_request_packet.h \
    make_send_reply_packet.h \
    get_target_data.h \
    get_sender_data.h \
    relay_normal_packet.h
