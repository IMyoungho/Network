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
    keyboard_event.cpp

HEADERS += \
    button_logic.h \
    parse.h \
    keyboard_event.h
