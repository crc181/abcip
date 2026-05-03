//--------------------------------------------------------------------- SOL
// This file is part of abcip, a simple packet crafting tool.
// Copyright (C) 2010-2026 Charles R. Combs
//
// Abcip is free software: you can redistribute it and/or modify it under
// the terms of the GNU General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your
// option) any later version.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.
//--------------------------------------------------------------------- EOL

//-------------------------------------------------------------------------
// parsing stuff
//-------------------------------------------------------------------------

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "cmd_parser.h"

#include <cstring>

#include "command.h"
#include "reader.h"
#include "status.h"

using namespace std;

//-------------------------------------------------------------------------
// lexer
//-------------------------------------------------------------------------

class Lexer {
public:
    Lexer(Reader*);
    ~Lexer();

    bool GetToken(string&);
    bool ReadBlock(string&);
    void GetLocation(int& line, int& pos);

    bool trace = false;

private:
    Reader* sin;
    int pos, line;
    char prev;
};

Lexer::Lexer (Reader* in) {
    sin = in;
    pos = 0;
    line = 1;
    prev = 0;
}

Lexer::~Lexer () {
    delete sin;
}

void Lexer::GetLocation (int& y, int& x) {
    y = line;
    x = prev ? pos-1 : pos;
}

bool Lexer::GetToken (string& tok) {
    int state = 0;
    char c;

    tok.clear();

    while ( prev || *sin >> c ) {
        if ( trace ) cerr << "Lexer state=" << state << " tok='" << tok << "'" << endl;

        if ( prev ) {
            c = prev;
            prev = 0;
        }
        else pos++;

        if ( c == '\n' ) {
            line++;
            pos = 0;
        }
        switch ( state ) {
        case 0:  // no token
            if ( isspace(c) ) {
                continue;
            }
            if ( c == '#' ) {
                state = 1;
                continue;
            }
            if ( c == '"' ) {
                tok += c;
                state = 2;
                continue;
            }
            if ( ispunct(c) && !strchr("+-$", c) ) {
                if ( !tok.empty() ) {  // GCOVR_EXCL_START -- state 0 tok is always empty
                    prev = c;
                    return true;
                }                      // GCOVR_EXCL_STOP
                tok += c;
                return true;
            }
            if ( c == '$' ) {
                tok += c;
                state = 7;
                continue;
            }
            tok += tolower(c);
            state = 3;
            break;

        case 1:  // comment
            if ( c == '\n' ) {
                state = 0;
            }
            break;

        case 2:  // string
            if ( c == '"' ) {
                state = 4;
                continue;
            } else if ( c == '\\' ) {
                state = 6;
            }
            tok += c;
            break;

        case 3:  // regular
            if ( isalnum(c) || (c == '.') ) {
                tok += tolower(c);
            } else {
                prev = c;
                return true;
            }
            break;

        case 7:  // $ sigil — accumulate name or return bare $
            if ( isalnum(c) || c == '_' ) {
                tok += tolower(c);
            } else {
                prev = c;
                return true;
            }
            break;

        case 4:
            if ( c == '"' ) {
                state = 2;
            } else if ( c == '#' ) {
                state = 5;
            } else if ( !isspace(c) ) {
                tok += '"';
                prev = c;
                return true;
            }
            break;

        case 5:
            if ( c == '\n' ) {
                state = 4;
            }
            break;

        case 6:
            tok += c;
            state = 2;
            break;
        }
    }
    // FIXTHIS return success/failure apart from
    // token; if last char is opening quote then
    // should return false for error.
    if ( state == 4 )
        tok += '"';
    return !tok.empty();
}

bool Lexer::ReadBlock (string& block) {
    int depth = 1;
    char c;
    block.clear();

    while ( *sin >> c ) {
        if ( c == '{' ) {
            depth++;
        } else if ( c == '}' ) {
            if ( --depth == 0 )
                return true;
        }
        block += c;
    }
    status.SetError("unclosed '{'", line, pos);
    return false;
}

//-------------------------------------------------------------------------
// parser
//-------------------------------------------------------------------------

class CommandParserImpl {
public:
    CommandParserImpl(Reader* in) : lexer(in) { }
    Option* NewOption(unsigned, const string&, const string&, const string&);

    Lexer lexer;
    string commands;
    bool bad = false;
    bool trace = false;
};

Option* CommandParserImpl::NewOption (
    unsigned idx, const string& key,
    const string& val, const string& proto
) {
    int y, x;
    lexer.GetLocation(y, x);
    Option* o = new Option(idx, key, val, proto);
    o->SetPos(y, x);
    return o;
}

CommandParser::CommandParser (Reader* in, const char* s, bool trace) {
    my = new CommandParserImpl(in);
    my->commands = s;
    my->trace = trace;
    my->lexer.trace = trace;
}

CommandParser::~CommandParser () {
    delete my;
}

bool CommandParser::Good () {
    return !my->bad;
}

void CommandParser::GetLocation (int& y, int& x) {
    my->lexer.GetLocation(y, x);
}

bool CommandParser::Load (Command& cmd) {
    string tok, key, proto, null = " ";
    unsigned index = 0;
    const char* err = nullptr;

    int state = 0;

    while ( !err && my->lexer.GetToken(tok) ) {
        if ( my->trace ) cerr << "Parser state=" << state << " tok='" << tok << "'" << endl;

        if ( tok == ")" ) {
            int line, pos;
            my->lexer.GetLocation(line, pos);
            status.SetPos(line, pos);
        }
        switch ( state ) {
        case 0:
            if ( tok[0] == '$' ) {
                string dollar = "$";
                cmd.SetName(dollar);
                if ( tok.length() > 1 ) {
                    // $name=value — name is the rest of the token
                    key = tok.substr(1);
                    state = 20;
                } else {
                    state = 22;
                }
            } else if ( tok == "let" ) {
                cmd.SetName(tok);
                state = 22;
            } else if ( isalnum(tok[0]) ) {
                key = tok;
                state = 1;
            } else {
                err = "expected alpha or digit";
            }
            break;

        case 1:
            if ( tok == ":" ) {
                cmd.SetContext(key);
                state = 2;
            } else if ( tok == "(" ) {
                if ( key == "r" || key == "repeat" ) {
                    cmd.SetName(key);
                    state = 30;
                } else if ( my->commands.find(key) != string::npos ) {
                    cmd.SetName(key);
                    state = 4;
                } else {
                    err = "unknown command";
                }
            } else {
                err = "expected ':' or '('";
            }
            break;

        case 2:
            if ( tok == "r" || tok == "repeat" ) {
                cmd.SetName(tok);
                state = 3;
            } else if ( my->commands.find(tok) != string::npos ) {
                cmd.SetName(tok);
                state = 3;
            } else {
                err = "unknown command";
            }
            break;

        case 3:
            if ( tok == "(" ) {
                string& name = cmd.GetName();
                state = (name == "r" || name == "repeat") ? 30 : 4;
            } else {
                err = "expected '('";
            }
            break;

        case 4:
            if ( isdigit(tok[0]) || tok[0] == '-' ) {
                index = atoi(tok.c_str());
                state = 5;
                break;
            }
            // Fall through
        case 6:
            if ( tok == ")" ) {
                return true;
            }
            if ( isalpha(tok[0]) ) {
                key = tok;
                state = 10;
            } else {
                err = "expected var";
            }
            break;

        case 5:
            if ( tok == ":" ) {
                state = 6;
                break;
            }
            err = "expected ':'";
            break;

        case 11:
            if ( isalpha(tok[0]) ) {
                key = tok;
                state = 7;
            } else {
                err = "expected var";
            }
            break;

        case 10:
            if ( tok == ":" ) {
                proto = key;
                key.clear();
                state = 11;
                break;
            }
            // Fall through
        case 7:
            if ( tok == ")" ) {
                cmd.AddOption(my->NewOption(index, key, null, proto));
                return true;
            } else if ( tok == "," ) {
                cmd.AddOption(my->NewOption(index, key, null, proto));
                state = 4;
            } else if ( tok == ";" ) {
                cmd.AddOption(my->NewOption(index, key, null, proto));
                index = 0;
                proto.clear();
                state = 4;
            } else if ( tok == "=" ) {
                state = 8;
            } else if ( tok == "+" ) {
                state = 12;
            } else {
                err = "expected '=', ',' or ')'";
            }
            break;

        case 8:
            // should ensure tok is ok value (eg not a ')')
            cmd.AddOption(my->NewOption(index, key, tok, proto));
            state = 9;
            break;

        case 12:  // key + — expect '='
            if ( tok == "=" ) {
                state = 13;
            } else {
                err = "expected '+='";
            }
            break;

        case 13:  // key += — expect delta value
        {
            Option* o = my->NewOption(index, key, tok, proto);
            o->delta = true;
            cmd.AddOption(o);
            state = 9;
            break;
        }

        case 9:
            if ( tok == ")" ) {
                return true;
            } else if ( tok == "," ) {
                state = 4;
            } else if ( tok == ";" ) {
                index = 0;
                proto.clear();
                state = 4;
            } else {
                err = "expected ',' or ')'";
            }
            break;

        case 20:  // $ name — expect '='
            if ( tok == "=" ) {
                state = 21;
            } else {
                err = "expected '='";
            }
            break;

        case 21:  // $ name = — expect value
            cmd.AddOption(my->NewOption(0, key, tok, string()));
            return true;

        case 22:  // bare $ — expect name token (space between $ and name)
            if ( isalpha(tok[0]) ) {
                key = tok;
                state = 20;
            } else {
                err = "expected variable name";
            }
            break;

        case 30:  // repeat( — expect count
            if ( isdigit(tok[0]) ) {
                cmd.AddOption(my->NewOption(0, "count", tok, string()));
                state = 31;
            } else {
                err = "expected repeat count";
            }
            break;

        case 31:  // repeat(N — expect ')'
            if ( tok == ")" ) {
                state = 32;
            } else {
                err = "expected ')'";
            }
            break;

        case 32:  // repeat(N) — expect '{'
            if ( tok == "{" ) {
                string body;
                if ( !my->lexer.ReadBlock(body) )
                    return false;
                cmd.AddOption(my->NewOption(0, "body", body, string()));
                return true;
            } else {
                err = "expected '{'";
            }
            break;

        default:                       // GCOVR_EXCL_LINE
            err = "unknown state";     // GCOVR_EXCL_LINE
        }
    }
    if ( state && !err )
        err = "incomplete command";

    if ( err ) {
        int line, pos;
        my->lexer.GetLocation(line, pos);
        status.SetError(err, line, pos);
        cerr << status << endl;
        my->bad = true;
    }
    return false;
}

