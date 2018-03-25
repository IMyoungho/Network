TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt
LIBS += -lpcap
LIBS += -lpthread
SOURCES += main.cpp \
    parse_data.cpp

HEADERS += \
    parse_data.h \
    parse_data_in_linux.h \
    char_to_binary.h \
    send_packet.h \
    get_gateway_data.h \
    make_request_packet.h \
    get_target_data.h \
    make_send_reply_packet.h \
    replay_normal_packet.h
