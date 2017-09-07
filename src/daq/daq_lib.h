//--------------------------------------------------------------------- SOL
// This file is part of abcip, a simple packet crafting tool.
// Copyright (C) 2010-2013 Charles R. Combs
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

#ifndef __DAQ_LIB_H__
#define __DAQ_LIB_H__

#include "abc_daq.h"

#define DAQ_CLASS AbcDaq
#define DAQ_NAME "abc"
#define DAQ_TYPE ( \
    DAQ_TYPE_FILE_CAPABLE | \
    DAQ_TYPE_INTF_CAPABLE | \
    DAQ_TYPE_MULTI_INSTANCE )
#define DAQ_VER  1

#endif

