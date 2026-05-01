#include <catch2/catch_all.hpp>

#include <daq_module_api.h>
#include <daq_dlt.h>

#include <cstdio>
#include <cstring>
#include <stdarg.h>
#include <pcap/pcap.h>

// -------------------------------------------------------------------------
// Minimal stub structs for the opaque DAQ config/instance handles
// -------------------------------------------------------------------------

struct _daq_module_config {
    const char* input;
    int snaplen;
    unsigned pool_size;
    // single variable slot (key=nullptr terminates)
    const char* var_key;
    const char* var_value;
    int var_done;
};

struct _daq_module_instance {
    char errbuf[256];
};

// -------------------------------------------------------------------------
// Stub DAQ_BaseAPI_t callbacks
// -------------------------------------------------------------------------

static const char* stub_config_get_input(DAQ_ModuleConfig_h cfg)
    { return cfg->input; }

static int stub_config_get_snaplen(DAQ_ModuleConfig_h cfg)
    { return cfg->snaplen; }

static unsigned stub_config_get_timeout(DAQ_ModuleConfig_h)
    { return 0; }

static unsigned stub_config_get_msg_pool_size(DAQ_ModuleConfig_h cfg)
    { return cfg->pool_size; }

static unsigned stub_config_get_total_instances(DAQ_ModuleConfig_h)
    { return 1; }

static unsigned stub_config_get_instance_id(DAQ_ModuleConfig_h)
    { return 0; }

static DAQ_Mode stub_config_get_mode(DAQ_ModuleConfig_h)
    { return DAQ_MODE_READ_FILE; }

static const char* stub_config_get_variable(DAQ_ModuleConfig_h cfg, const char* key)
{
    if (cfg->var_key && strcmp(cfg->var_key, key) == 0)
        return cfg->var_value;
    return nullptr;
}

static int stub_config_first_variable(DAQ_ModuleConfig_h cfg, const char** key, const char** value)
{
    cfg->var_done = 0;
    if (cfg->var_key) {
        *key = cfg->var_key;
        *value = cfg->var_value;
    } else {
        *key = nullptr;
        *value = nullptr;
    }
    return 0;
}

static int stub_config_next_variable(DAQ_ModuleConfig_h cfg, const char** key, const char** value)
{
    cfg->var_done = 1;
    *key = nullptr;
    *value = nullptr;
    return 0;
}

static int stub_resolve_subapi(DAQ_ModuleInstance_h, DAQ_InstanceAPI_t*)
    { return DAQ_ERROR_NOTSUP; }

static void stub_set_errbuf(DAQ_ModuleInstance_h inst, const char* fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(inst->errbuf, sizeof(inst->errbuf), fmt, ap);
    va_end(ap);
}

static DAQ_BaseAPI_t make_base_api()
{
    DAQ_BaseAPI_t api;
    memset(&api, 0, sizeof(api));
    api.api_version             = DAQ_BASE_API_VERSION;
    api.api_size                = sizeof(DAQ_BaseAPI_t);
    api.config_get_input        = stub_config_get_input;
    api.config_get_snaplen      = stub_config_get_snaplen;
    api.config_get_timeout      = stub_config_get_timeout;
    api.config_get_msg_pool_size = stub_config_get_msg_pool_size;
    api.config_get_total_instances = stub_config_get_total_instances;
    api.config_get_instance_id  = stub_config_get_instance_id;
    api.config_get_mode         = stub_config_get_mode;
    api.config_get_variable     = stub_config_get_variable;
    api.config_first_variable   = stub_config_first_variable;
    api.config_next_variable    = stub_config_next_variable;
    api.resolve_subapi          = stub_resolve_subapi;
    api.set_errbuf              = stub_set_errbuf;
    return api;
}

// -------------------------------------------------------------------------
// The module API exported by daq_lib.cc
// -------------------------------------------------------------------------

extern "C" DAQ_ModuleAPI_t DAQ_MODULE_DATA;

// -------------------------------------------------------------------------
// Tests
// -------------------------------------------------------------------------

TEST_CASE("DAQ module load/unload succeeds", "[daq]") {
    DAQ_BaseAPI_t api = make_base_api();
    CHECK(DAQ_MODULE_DATA.load(&api) == DAQ_SUCCESS);
    CHECK(DAQ_MODULE_DATA.unload() == DAQ_SUCCESS);
}

TEST_CASE("DAQ module load fails with wrong api_version", "[daq]") {
    DAQ_BaseAPI_t api = make_base_api();
    api.api_version = 0;
    CHECK(DAQ_MODULE_DATA.load(&api) == DAQ_ERROR);
}

TEST_CASE("DAQ module load fails with wrong api_size", "[daq]") {
    DAQ_BaseAPI_t api = make_base_api();
    api.api_size = 0;
    CHECK(DAQ_MODULE_DATA.load(&api) == DAQ_ERROR);
}

TEST_CASE("DAQ get_variable_descs returns 0", "[daq]") {
    const DAQ_VariableDesc_t* descs = nullptr;
    CHECK(DAQ_MODULE_DATA.get_variable_descs(&descs) == 0);
}

TEST_CASE("DAQ instantiate and destroy with minimal config", "[daq]") {
    DAQ_BaseAPI_t api = make_base_api();
    REQUIRE(DAQ_MODULE_DATA.load(&api) == DAQ_SUCCESS);

    struct _daq_module_config cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.input     = "/dev/null";
    cfg.snaplen   = 1518;
    cfg.pool_size = 4;
    cfg.var_key   = nullptr;

    struct _daq_module_instance inst;
    memset(&inst, 0, sizeof(inst));

    void* handle = nullptr;
    int rc = DAQ_MODULE_DATA.instantiate(&cfg, &inst, &handle);
    REQUIRE(rc == DAQ_SUCCESS);
    REQUIRE(handle != nullptr);

    DAQ_MODULE_DATA.destroy(handle);
    DAQ_MODULE_DATA.unload();
}

TEST_CASE("DAQ start and stop", "[daq]") {
    DAQ_BaseAPI_t api = make_base_api();
    REQUIRE(DAQ_MODULE_DATA.load(&api) == DAQ_SUCCESS);

    struct _daq_module_config cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.input = "/dev/null";
    cfg.snaplen = 1518;
    cfg.pool_size = 4;

    struct _daq_module_instance inst;
    memset(&inst, 0, sizeof(inst));

    void* handle = nullptr;
    REQUIRE(DAQ_MODULE_DATA.instantiate(&cfg, &inst, &handle) == DAQ_SUCCESS);

    CHECK(DAQ_MODULE_DATA.start(handle) == DAQ_SUCCESS);
    CHECK(DAQ_MODULE_DATA.stop(handle) == DAQ_SUCCESS);

    DAQ_MODULE_DATA.destroy(handle);
    DAQ_MODULE_DATA.unload();
}

TEST_CASE("DAQ get_snaplen returns configured value", "[daq]") {
    DAQ_BaseAPI_t api = make_base_api();
    REQUIRE(DAQ_MODULE_DATA.load(&api) == DAQ_SUCCESS);

    struct _daq_module_config cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.input = "/dev/null";
    cfg.snaplen = 1518;
    cfg.pool_size = 4;

    struct _daq_module_instance inst;
    memset(&inst, 0, sizeof(inst));

    void* handle = nullptr;
    REQUIRE(DAQ_MODULE_DATA.instantiate(&cfg, &inst, &handle) == DAQ_SUCCESS);

    CHECK(DAQ_MODULE_DATA.get_snaplen(handle) == 1518);

    DAQ_MODULE_DATA.destroy(handle);
    DAQ_MODULE_DATA.unload();
}

TEST_CASE("DAQ get_capabilities returns expected flags", "[daq]") {
    DAQ_BaseAPI_t api = make_base_api();
    REQUIRE(DAQ_MODULE_DATA.load(&api) == DAQ_SUCCESS);

    struct _daq_module_config cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.input = "/dev/null";
    cfg.snaplen = 1518;
    cfg.pool_size = 4;

    struct _daq_module_instance inst;
    memset(&inst, 0, sizeof(inst));

    void* handle = nullptr;
    REQUIRE(DAQ_MODULE_DATA.instantiate(&cfg, &inst, &handle) == DAQ_SUCCESS);

    uint32_t caps = DAQ_MODULE_DATA.get_capabilities(handle);
    CHECK(caps & DAQ_CAPA_REPLACE);
    CHECK(caps & DAQ_CAPA_UNPRIV_START);
    CHECK(caps & DAQ_CAPA_INTERRUPT);

    DAQ_MODULE_DATA.destroy(handle);
    DAQ_MODULE_DATA.unload();
}

TEST_CASE("DAQ get_datalink_type returns DLT_EN10MB for eth stack", "[daq]") {
    DAQ_BaseAPI_t api = make_base_api();
    REQUIRE(DAQ_MODULE_DATA.load(&api) == DAQ_SUCCESS);

    struct _daq_module_config cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.input = "/dev/null";
    cfg.snaplen = 1518;
    cfg.pool_size = 4;

    struct _daq_module_instance inst;
    memset(&inst, 0, sizeof(inst));

    void* handle = nullptr;
    REQUIRE(DAQ_MODULE_DATA.instantiate(&cfg, &inst, &handle) == DAQ_SUCCESS);

    CHECK(DAQ_MODULE_DATA.get_datalink_type(handle) == DLT_EN10MB);

    DAQ_MODULE_DATA.destroy(handle);
    DAQ_MODULE_DATA.unload();
}

TEST_CASE("DAQ get_stats and reset_stats", "[daq]") {
    DAQ_BaseAPI_t api = make_base_api();
    REQUIRE(DAQ_MODULE_DATA.load(&api) == DAQ_SUCCESS);

    struct _daq_module_config cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.input = "/dev/null";
    cfg.snaplen = 1518;
    cfg.pool_size = 4;

    struct _daq_module_instance inst;
    memset(&inst, 0, sizeof(inst));

    void* handle = nullptr;
    REQUIRE(DAQ_MODULE_DATA.instantiate(&cfg, &inst, &handle) == DAQ_SUCCESS);

    DAQ_Stats_t stats;
    CHECK(DAQ_MODULE_DATA.get_stats(handle, &stats) == DAQ_SUCCESS);
    CHECK(stats.packets_received == 0);

    DAQ_MODULE_DATA.reset_stats(handle);

    DAQ_MODULE_DATA.destroy(handle);
    DAQ_MODULE_DATA.unload();
}

TEST_CASE("DAQ get_msg_pool_info returns configured pool size", "[daq]") {
    DAQ_BaseAPI_t api = make_base_api();
    REQUIRE(DAQ_MODULE_DATA.load(&api) == DAQ_SUCCESS);

    struct _daq_module_config cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.input = "/dev/null";
    cfg.snaplen = 1518;
    cfg.pool_size = 8;

    struct _daq_module_instance inst;
    memset(&inst, 0, sizeof(inst));

    void* handle = nullptr;
    REQUIRE(DAQ_MODULE_DATA.instantiate(&cfg, &inst, &handle) == DAQ_SUCCESS);

    DAQ_MsgPoolInfo_t info;
    CHECK(DAQ_MODULE_DATA.get_msg_pool_info(handle, &info) == DAQ_SUCCESS);
    CHECK(info.size == 8);
    CHECK(info.available == 8);

    DAQ_MODULE_DATA.destroy(handle);
    DAQ_MODULE_DATA.unload();
}

TEST_CASE("DAQ interrupt sets interrupted state", "[daq]") {
    DAQ_BaseAPI_t api = make_base_api();
    REQUIRE(DAQ_MODULE_DATA.load(&api) == DAQ_SUCCESS);

    struct _daq_module_config cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.input = "/dev/null";
    cfg.snaplen = 1518;
    cfg.pool_size = 4;

    struct _daq_module_instance inst;
    memset(&inst, 0, sizeof(inst));

    void* handle = nullptr;
    REQUIRE(DAQ_MODULE_DATA.instantiate(&cfg, &inst, &handle) == DAQ_SUCCESS);

    CHECK(DAQ_MODULE_DATA.interrupt(handle) == DAQ_SUCCESS);

    DAQ_MODULE_DATA.destroy(handle);
    DAQ_MODULE_DATA.unload();
}

TEST_CASE("DAQ ioctl unsupported command returns error", "[daq]") {
    DAQ_BaseAPI_t api = make_base_api();
    REQUIRE(DAQ_MODULE_DATA.load(&api) == DAQ_SUCCESS);

    struct _daq_module_config cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.input = "/dev/null";
    cfg.snaplen = 1518;
    cfg.pool_size = 4;

    struct _daq_module_instance inst;
    memset(&inst, 0, sizeof(inst));

    void* handle = nullptr;
    REQUIRE(DAQ_MODULE_DATA.instantiate(&cfg, &inst, &handle) == DAQ_SUCCESS);

    CHECK(DAQ_MODULE_DATA.ioctl(handle, DIOCTL_GET_DEVICE_INDEX, nullptr, 0) == DAQ_ERROR_NOTSUP);

    DAQ_MODULE_DATA.destroy(handle);
    DAQ_MODULE_DATA.unload();
}

TEST_CASE("DAQ msg_receive on /dev/null returns EOF", "[daq]") {
    DAQ_BaseAPI_t api = make_base_api();
    REQUIRE(DAQ_MODULE_DATA.load(&api) == DAQ_SUCCESS);

    struct _daq_module_config cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.input = "/dev/null";
    cfg.snaplen = 1518;
    cfg.pool_size = 4;

    struct _daq_module_instance inst;
    memset(&inst, 0, sizeof(inst));

    void* handle = nullptr;
    REQUIRE(DAQ_MODULE_DATA.instantiate(&cfg, &inst, &handle) == DAQ_SUCCESS);

    const DAQ_Msg_t* msgs[4] = {};
    DAQ_RecvStatus rstat = DAQ_RSTAT_OK;
    DAQ_MODULE_DATA.msg_receive(handle, 4, msgs, &rstat);
    CHECK(rstat == DAQ_RSTAT_EOF);

    DAQ_MODULE_DATA.destroy(handle);
    DAQ_MODULE_DATA.unload();
}

// -------------------------------------------------------------------------
// Helper: read all packet data from a pcap file into a vector of byte vectors
// -------------------------------------------------------------------------

static std::vector<std::vector<uint8_t>> read_pcap_packets(const char* path)
{
    std::vector<std::vector<uint8_t>> result;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* p = pcap_open_offline(path, errbuf);
    if (!p) return result;
    struct pcap_pkthdr* hdr;
    const uint8_t* data;
    while (pcap_next_ex(p, &hdr, &data) == 1)
        result.push_back(std::vector<uint8_t>(data, data + hdr->caplen));
    pcap_close(p);
    return result;
}

TEST_CASE("DAQ msg_receive arp.abc matches ref pcap", "[daq]") {
    DAQ_BaseAPI_t api = make_base_api();
    REQUIRE(DAQ_MODULE_DATA.load(&api) == DAQ_SUCCESS);

    struct _daq_module_config cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.input   = ARP_ABC;
    cfg.snaplen = 65535;
    cfg.pool_size = 16;

    struct _daq_module_instance inst;
    memset(&inst, 0, sizeof(inst));

    void* handle = nullptr;
    REQUIRE(DAQ_MODULE_DATA.instantiate(&cfg, &inst, &handle) == DAQ_SUCCESS);

    // Collect all packets via msg_receive
    std::vector<std::vector<uint8_t>> got;
    const DAQ_Msg_t* msgs[16] = {};
    DAQ_RecvStatus rstat = DAQ_RSTAT_OK;
    while (rstat == DAQ_RSTAT_OK) {
        unsigned n = DAQ_MODULE_DATA.msg_receive(handle, 16, msgs, &rstat);
        for (unsigned i = 0; i < n; i++) {
            const DAQ_Msg_t* msg = msgs[i];
            got.push_back(std::vector<uint8_t>(msg->data, msg->data + msg->data_len));
            DAQ_MODULE_DATA.msg_finalize(handle, msg, DAQ_VERDICT_PASS);
        }
    }
    CHECK(rstat == DAQ_RSTAT_EOF);

    // Compare against ref pcap
    auto ref = read_pcap_packets(ARP_REF);
    REQUIRE(got.size() == ref.size());
    for (size_t i = 0; i < got.size(); i++)
        CHECK(got[i] == ref[i]);

    DAQ_MODULE_DATA.destroy(handle);
    DAQ_MODULE_DATA.unload();
}

TEST_CASE("DAQ msg_receive returns stats after receiving packets", "[daq]") {
    DAQ_BaseAPI_t api = make_base_api();
    REQUIRE(DAQ_MODULE_DATA.load(&api) == DAQ_SUCCESS);

    struct _daq_module_config cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.input   = ARP_ABC;
    cfg.snaplen = 65535;
    cfg.pool_size = 16;

    struct _daq_module_instance inst;
    memset(&inst, 0, sizeof(inst));

    void* handle = nullptr;
    REQUIRE(DAQ_MODULE_DATA.instantiate(&cfg, &inst, &handle) == DAQ_SUCCESS);

    const DAQ_Msg_t* msgs[16] = {};
    DAQ_RecvStatus rstat = DAQ_RSTAT_OK;
    unsigned total = 0;
    while (rstat == DAQ_RSTAT_OK) {
        unsigned n = DAQ_MODULE_DATA.msg_receive(handle, 16, msgs, &rstat);
        for (unsigned i = 0; i < n; i++)
            DAQ_MODULE_DATA.msg_finalize(handle, msgs[i], DAQ_VERDICT_PASS);
        total += n;
    }

    DAQ_Stats_t stats;
    DAQ_MODULE_DATA.get_stats(handle, &stats);
    CHECK(stats.packets_received == total);

    DAQ_MODULE_DATA.destroy(handle);
    DAQ_MODULE_DATA.unload();
}
