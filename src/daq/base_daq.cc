#include "base_daq.h"

#include <daq_dlt.h>

int Daq::SetFilter(const char*) { return DAQ_ERROR_NOTSUP; }

int Daq::Start() { return DAQ_SUCCESS; }
int Daq::Inject(DAQ_MsgType, const void*, const uint8_t*, uint32_t) { return DAQ_ERROR_NOTSUP; }
int Daq::InjectRelative(const DAQ_Msg_t*, const uint8_t*, uint32_t, int) { return DAQ_ERROR_NOTSUP; }
int Daq::Interrupt() { return DAQ_ERROR_NOTSUP; }
int Daq::Stop() { return DAQ_SUCCESS; }
int Daq::Ioctl(DAQ_IoctlCmd, void*, size_t) { return DAQ_ERROR_NOTSUP; }

int Daq::GetStats(DAQ_Stats_t*) { return DAQ_ERROR_NOTSUP; }
void Daq::ResetStats() { }

int Daq::GetSnaplen() { return -1; }
uint32_t Daq::GetCapabilities() { return 0; }
int Daq::GetDatalinkType() { return DLT_NULL; }

unsigned Daq::MsgReceive(const unsigned, const DAQ_Msg_t**, DAQ_RecvStatus*) { return DAQ_ERROR_NOTSUP; }
int Daq::MsgFinalize(const DAQ_Msg_t*, DAQ_Verdict) { return DAQ_ERROR_NOTSUP; }
int Daq::GetMsgPoolInfo(DAQ_MsgPoolInfo_t*) { return DAQ_ERROR_NOTSUP; }
