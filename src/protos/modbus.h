#ifndef __MODBUS_H__
#define __MODBUS_H__

#include "protocol.h"

class ModbusProtocol : public Protocol {
public:
    ModbusProtocol();
    ~ ModbusProtocol() override;

    const uint8_t* GetHeader(Packet&, uint32_t&) override;

    static Pimp* GetPimp();

private:
    class ModbusImpl* my;
};

#ifdef __PROTOTOOL_TAG__
#include "modbus.h"
PROTOTOOL_NEW(ModbusProtocol);
#endif

#endif

