#include <catch2/catch_all.hpp>

#include <sstream>
#include <string>
#include <vector>

#include "abc_io.h"
#include "command.h"
#include "packet.h"
#include "parser.h"
#include "status.h"
#include "writer.h"

// -------------------------------------------------------------------------
// Stubs
// -------------------------------------------------------------------------

struct ScriptOpt {
    std::string proto;  // layer proto (may be empty)
    std::string key;
    std::string value;
};

struct ScriptCmd {
    std::string name;
    std::string context;
    std::vector<ScriptOpt> opts;
};

class ScriptParser : public Parser {
public:
    ScriptParser(std::vector<ScriptCmd> cmds) : cmds(std::move(cmds)), idx(0), good(true) { }

    bool Load(Command& cmd) override {
        if (idx >= cmds.size()) return false;
        const ScriptCmd& s = cmds[idx++];
        std::string name = s.name;
        std::string ctx  = s.context;
        cmd.SetName(name);
        cmd.SetContext(ctx);
        for (auto& o : s.opts)
            cmd.AddOption(new Option(0, o.key, o.value, o.proto));
        return true;
    }
    bool Good() override { return good; }
    void GetLocation(int& y, int& x) override { y = x = 0; }

    std::vector<ScriptCmd> cmds;
    size_t idx;
    bool good;
};

class CountingWriter : public Writer {
public:
    void operator<<(const Packet&) override { count++; }
    unsigned GetWrittenAmount() override { return count; }
    void SetMaxWrittenSize(unsigned v) override { max = v; }
    unsigned count = 0;
    unsigned max = 0;
};

// status is a global that persists across tests; reset it before each test
struct StatusGuard {
    StatusGuard() { status = Status(); }
};

// Helper: build ScriptCmd opts from {key, value} pairs (no proto)
static ScriptCmd make_cmd(
    std::string name, std::string ctx,
    std::vector<std::pair<std::string,std::string>> kvs)
{
    ScriptCmd c;
    c.name = std::move(name);
    c.context = std::move(ctx);
    for (auto& kv : kvs)
        c.opts.push_back({"", kv.first, kv.second});
    return c;
}

static AbcIo* make_io(std::vector<ScriptCmd> cmds, bool trace = false)
{
    auto* p = new ScriptParser(std::move(cmds));
    auto* w = new CountingWriter;
    return new AbcIo(p, w, DEFAULT_STACK, DEFAULT_USER, trace);
}

// Suppress cerr during tests that exercise error paths
struct SuppressCerr {
    SuppressCerr() : old(std::cerr.rdbuf(ss.rdbuf())) { }
    ~SuppressCerr() { std::cerr.rdbuf(old); }
    std::ostringstream ss;
    std::streambuf* old;
};

// -------------------------------------------------------------------------
// Basic execution
// -------------------------------------------------------------------------

TEST_CASE("AbcIo empty input returns 0", "[abc_io]") {
    StatusGuard sg;
    AbcIo* io = make_io({});
    CHECK(io->Execute(100) == 0);
    delete io;
}

TEST_CASE("AbcIo a command produces packet and returns 1", "[abc_io]") {
    StatusGuard sg;
    AbcIo* io = make_io({ make_cmd("a", "", {{"syn", " "}}) });
    CHECK(io->Execute(100) == 1);
    delete io;
}

TEST_CASE("AbcIo b command produces packet", "[abc_io]") {
    StatusGuard sg;
    AbcIo* io = make_io({
        make_cmd("a", "", {{"syn", " "}}),
        make_cmd("b", "", {{"syn", " "}, {"ack", "1"}}),
    });
    CHECK(io->Execute(100) == 2);
    delete io;
}

TEST_CASE("AbcIo c command configures session", "[abc_io]") {
    StatusGuard sg;
    ScriptCmd cfg;
    cfg.name = "c";
    cfg.opts.push_back({"ip4", "a", "\"10.0.0.1\""});
    AbcIo* io = make_io({
        cfg,
        make_cmd("a", "", {{"syn", " "}}),
    });
    CHECK(io->Execute(100) == 2);
    delete io;
}

TEST_CASE("AbcIo d command defines stack", "[abc_io]") {
    StatusGuard sg;
    AbcIo* io = make_io({ make_cmd("d", "", {{"stack", "\"eth:ip4:tcp\""}}) });
    CHECK(io->Execute(100) == 1);
    delete io;
}

// -------------------------------------------------------------------------
// Trace path (exercises Dump)
// -------------------------------------------------------------------------

TEST_CASE("AbcIo trace=true calls Dump without crashing", "[abc_io]") {
    StatusGuard sg;
    SuppressCerr sc;
    AbcIo* io = make_io({ make_cmd("a", "", {{"syn", " "}}) }, true);
    CHECK(io->Execute(100) == 1);
    delete io;
}

TEST_CASE("AbcIo trace dumps index and proto fields", "[abc_io]") {
    StatusGuard sg;
    SuppressCerr sc;
    AbcIo* io = make_io({ make_cmd("a", "", {{"syn", " "}}) }, true);
    io->Execute(100);
    delete io;
    CHECK_FALSE(sc.ss.str().empty());
}

// -------------------------------------------------------------------------
// Interrupt path
// -------------------------------------------------------------------------

TEST_CASE("AbcIo Interrupt stops execution", "[abc_io]") {
    StatusGuard sg;
    AbcIo* io = make_io({
        make_cmd("a", "", {{"syn", " "}}),
        make_cmd("a", "", {{"ack", " "}}),
    });
    io->Interrupt();
    int n = io->Execute(100);
    CHECK(n == 0);
    delete io;
}

// -------------------------------------------------------------------------
// Error paths
// -------------------------------------------------------------------------

TEST_CASE("AbcIo bad stack in d command returns -1", "[abc_io]") {
    StatusGuard sg;
    SuppressCerr sc;
    AbcIo* io = make_io({ make_cmd("d", "", {{"stack", "eth:ip4:tcp"}}) });
    CHECK(io->Execute(100) == -1);
    delete io;
}

TEST_CASE("AbcIo undefined named context returns -1", "[abc_io]") {
    StatusGuard sg;
    SuppressCerr sc;
    AbcIo* io = make_io({ make_cmd("a", "nosuchctx", {{"syn", " "}}) });
    CHECK(io->Execute(100) == -1);
    delete io;
}

TEST_CASE("AbcIo unknown variable returns -1", "[abc_io]") {
    StatusGuard sg;
    SuppressCerr sc;
    AbcIo* io = make_io({ make_cmd("a", "", {{"nosuchvar", "1"}}) });
    CHECK(io->Execute(100) == -1);
    delete io;
}

TEST_CASE("AbcIo parser Good()=false returns -1", "[abc_io]") {
    StatusGuard sg;
    auto* p = new ScriptParser({});
    p->good = false;
    auto* w = new CountingWriter;
    AbcIo io(p, w, DEFAULT_STACK, DEFAULT_USER, false);
    CHECK(io.Execute(100) == -1);
}

// -------------------------------------------------------------------------
// HelpDefine
// -------------------------------------------------------------------------

TEST_CASE("AbcIo::HelpDefine produces output", "[abc_io]") {
    std::ostringstream out;
    AbcIo::HelpDefine(out);
    CHECK_FALSE(out.str().empty());
    CHECK(out.str().find("stack") != std::string::npos);
}

// -------------------------------------------------------------------------
// Named contexts
// -------------------------------------------------------------------------

TEST_CASE("AbcIo named context d then a", "[abc_io]") {
    StatusGuard sg;
    AbcIo* io = make_io({
        make_cmd("d", "sess1", {{"stack", "\"eth:ip4:tcp\""}}),
        make_cmd("a", "sess1", {{"syn", " "}}),
    });
    CHECK(io->Execute(100) == 2);
    delete io;
}

TEST_CASE("AbcIo redefine default context with d", "[abc_io]") {
    StatusGuard sg;
    AbcIo* io = make_io({
        make_cmd("d", "", {{"stack", "\"eth:ip4:tcp\""}}),
        make_cmd("d", "", {{"stack", "\"eth:ip4:udp\""}}),
        make_cmd("a", "", {}),
    });
    CHECK(io->Execute(100) == 3);
    delete io;
}
