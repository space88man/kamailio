/*
 * Copyright (C) 2012 sip-router.org
 *
 * This file is part of Kamailio, a free SIP server.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Kamailio is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 * Kamailio is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#ifndef _CTL_MOD_H_
#define _CTL_MOD_H_

#ifdef CTL_SYSTEM_MALLOC
#include <stdlib.h>
#define ctl_malloc malloc
#define ctl_realloc realloc
#define ctl_free free
#else
#include "../../core/mem/mem.h"
#define ctl_malloc pkg_malloc
#define ctl_realloc pkg_realloc
#define ctl_free pkg_free
#endif

#endif
