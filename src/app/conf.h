#ifndef __CONF_H__
#define __CONF_H__

#include <cstdint>
#include <iosfwd>

class Conf {
public:
    Conf(int argc, char* argv[], std::ostream& out = get_cout());

public:
    const char* pcap;
    const char* stack;
    const char* user;
    uint16_t snap;
    bool trace, raw, done;

private:
    static std::ostream& get_cout();
};

#endif
