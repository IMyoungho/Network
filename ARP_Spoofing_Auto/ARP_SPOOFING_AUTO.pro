TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt
LIBS += -lpcap
LIBS += -lpthread
SOURCES += \
        main.cpp \
    parse.cpp \
    setting_map.cpp \
    keyboard_event.cpp \
    convert_type.cpp

HEADERS += \
    parse.h \
    setting_map.h \
    keyboard_event.h \
    convert_type.h
