TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt
LIBS += -lpcap
LIBS += -lpthread
SOURCES += \
        main.cpp \
    button_logic.cpp \
    parse.cpp \
    keyboard_event.cpp \
    convert_type.cpp \
    setting_map.cpp \
    module_r.cpp \
    module_a.cpp

HEADERS += \
    button_logic.h \
    parse.h \
    keyboard_event.h \
    arp_header.h \
    convert_type.h \
    setting_map.h \
    module_a.h \
    module_r.h
