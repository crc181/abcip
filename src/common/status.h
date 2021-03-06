//--------------------------------------------------------------------- SOL
// This file is part of abcip, a simple packet crafting tool.
// Copyright (C) 2010-2017 Charles R. Combs
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
// status stuff
//-------------------------------------------------------------------------

#ifndef __STATUS_H__
#define __STATUS_H__

#include <iostream>

class Status {
public:
    Status() = default;

    void SetError(const char* s, unsigned r, unsigned c)
        { err = s; ok = false; row = r; col = c; }

    void SetError(const char* s = nullptr)
        { err = s; ok = false; }

    void SetPos(unsigned r, unsigned c)
        { row = r; col = c; }

    void GetPos(unsigned& r, unsigned& c) const
        { r = row; c = col; }

    const char* GetError() const
        { return err; }

    bool Ok() const
        { return ok; }

private:
    bool ok = true;
    unsigned row = 0;
    unsigned col = 0;
    const char* err = nullptr;
};

extern Status status;

std::ostream& operator<< (std::ostream&, const Status&);

#endif

