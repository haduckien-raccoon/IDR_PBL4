//--------------------------------------------------------------------------
// Copyright (C) 2019-2024 Cisco and/or its affiliates. All rights reserved.
//
// This file may contain proprietary rules that were created, tested and
// certified by Sourcefire, Inc. (the "VRT Certified Rules") as well as
// rules that were created by Sourcefire and other third parties and
// distributed under the GNU General Public License (the "GPL Rules").
// The VRT Certified Rules contained in this file are the property of
// Sourcefire, Inc. Copyright 2005 Sourcefire, Inc. All Rights Reserved.
// The GPL Rules created by Sourcefire, Inc. are the property of
// Sourcefire, Inc. Copyright 2002-2005 Sourcefire, Inc. All Rights
// Reserved. All other GPL Rules are owned and copyrighted by their
// respective owners (please see www.snort.org/contributors for a list
// of owners and their respective copyrights). In order to determine what
// rules are VRT Certified Rules or GPL Rules, please refer to the VRT
// Certified Rules License Agreement.
//--------------------------------------------------------------------------
// os-windows_microsoft-gdi-tiff-memory-corruption.cc author Brandon Stultz <brastult@cisco.com>

#include "framework/cursor.h"
#include "framework/so_rule.h"
#include "main/snort_types.h"
#include "protocols/packet.h"
#include "util_read.h"

#if(BASE_API_VERSION >= 20)
#include "detection/extract.h"
#else
namespace snort
{
int GetVarValueByIndex(uint32_t*, uint8_t);
}
#endif

//#define DEBUG
#ifdef DEBUG
#define DEBUG_SO(code) code
#else
#define DEBUG_SO(code)
#endif

using namespace snort;

static const char* rule_28487 = R"[Snort_SO_Rule](
alert file (
    msg:"OS-WINDOWS Microsoft GDI library TIFF handling memory corruption attempt";
    soid:28487;
    file_data;
    content:"II|2A 00|",fast_pattern;
    content:!"Exif",distance -10,within 4;
    byte_extract:4,0,ifd_offset,relative,little;
    byte_jump:4,-4,relative,little,post_offset -8;
    so:eval,relative;
    content:"|02 02 04 00 01 00 00 00|",distance 0;
    metadata:policy max-detect-ips drop;
    reference:cve,2013-3906;
    reference:url,technet.microsoft.com/en-us/security/bulletin/MS13-096;
    classtype:attempted-user;
    gid:3; sid:28487; rev:4;
)
)[Snort_SO_Rule]";

static const unsigned rule_28487_len = 0;

static const char* rule_28488 = R"[Snort_SO_Rule](
alert file (
    msg:"OS-WINDOWS Microsoft GDI library TIFF handling memory corruption attempt";
    soid:28488;
    file_data;
    content:"MM|00 2A|",fast_pattern;
    content:!"Exif",distance -10,within 4;
    byte_extract:4,0,ifd_offset,relative;
    byte_jump:4,-4,relative,post_offset -8;
    so:eval,relative;
    content:"|02 02 00 04 00 00 00 01|",distance 0;
    metadata:policy max-detect-ips drop;
    reference:cve,2013-3906;
    reference:url,technet.microsoft.com/en-us/security/bulletin/MS13-096;
    classtype:attempted-user;
    gid:3; sid:28488; rev:4;
)
)[Snort_SO_Rule]";

static const unsigned rule_28488_len = 0;

enum class Endian { BIG, LITTLE };

static inline uint32_t read_32(const uint8_t* p, Endian e)
{
    return (e == Endian::BIG) ? read_big_32(p) : read_little_32(p);
}

static inline uint16_t read_16(const uint8_t* p, Endian e)
{
    return (e == Endian::BIG) ? read_big_16(p) : read_little_16(p);
}

static IpsOption::EvalStatus DetectGdiMemoryCorruption(Cursor& c, Endian e)
{
    const uint8_t *cursor_normal = c.start(),
                  *cursor_start = c.start(),
                  *beg_of_buffer = c.buffer(),
                  *end_of_buffer = c.endo();

    uint32_t ifd_offset, strip_counts_val,
             num_strip_counts = 0;

    // get the ifd_offset from byte_extract
    if(GetVarValueByIndex(&ifd_offset, 0))
        return IpsOption::NO_MATCH;

    // check if we can read ifd_entry_count
    if(cursor_normal + 2 > end_of_buffer)
        return IpsOption::NO_MATCH;

    uint16_t ifd_entry_count = read_16(cursor_normal, e);
    cursor_normal += 2;

    DEBUG_SO(fprintf(stderr,"ifd_entry_count = 0x%04x\n",ifd_entry_count);)

    // limit ifd_entry_count
    if(ifd_entry_count > 15)
        ifd_entry_count = 15;

    // look for a StripByteCounts record (0x0117)
    for(unsigned i = 0; i < ifd_entry_count; i++)
    {
        // check if we can read the IFD
        if(cursor_normal + 12 > end_of_buffer)
            return IpsOption::NO_MATCH;

        uint16_t tag_id = read_16(cursor_normal, e);

        DEBUG_SO(fprintf(stderr,"tag_id = 0x%04x\n",tag_id);)

        if(tag_id != 0x0117)
        {
            cursor_normal += 12;
            continue;
        }

        // found a StripByteCounts record
        // read num_strip_counts and strip_counts_val
        num_strip_counts = read_32(cursor_normal+4, e);
        strip_counts_val = read_32(cursor_normal+8, e);
        DEBUG_SO(fprintf(stderr,"num_strip_counts = 0x%08x\n",num_strip_counts);)
        DEBUG_SO(fprintf(stderr,"strip_counts_val = 0x%08x\n",strip_counts_val);)
        break;
    }

    // if no rec found, bail
    if(num_strip_counts == 0)
        return IpsOption::NO_MATCH;

    if(num_strip_counts == 1)
    {
        // trivial, strip_counts_val is the val to check
        // if the MSB is not 0, then the jpegStreamSize
        // is sufficently large to alert
        return (strip_counts_val & 0xFF000000) ?
            IpsOption::MATCH : IpsOption::NO_MATCH;
    }

    // strip_counts_val is an offset
    // to an array of strip counts
    if(strip_counts_val < ifd_offset)
    {
        // strip counts is before IFD
        strip_counts_val = ifd_offset - strip_counts_val;

        // check if we can jump to strip_counts_val
        if(strip_counts_val > cursor_start - beg_of_buffer)
            return IpsOption::NO_MATCH;

        cursor_normal = cursor_start - strip_counts_val;
    }
    else if(strip_counts_val > ifd_offset)
    {
        // strip counts is after IFD
        strip_counts_val = strip_counts_val - ifd_offset;

        // check if we can jump to strip_counts_val
        if(strip_counts_val > end_of_buffer - cursor_start)
            return IpsOption::NO_MATCH;

        cursor_normal = cursor_start + strip_counts_val;
    }
    else
    {
        // invalid strip counts offset
        return IpsOption::NO_MATCH;
    }

    // limit num_strip_counts
    if(num_strip_counts > 15)
        num_strip_counts = 15;

    for(unsigned i = 0; i < num_strip_counts; i++)
    {
        if(cursor_normal + 4 > end_of_buffer)
            return IpsOption::NO_MATCH;

        uint32_t val = read_32(cursor_normal, e);

        DEBUG_SO(fprintf(stderr,"val = 0x%08x\n",val);)

        if(val & 0xFF000000)
            return IpsOption::MATCH;

        cursor_normal += 4;
    }

    return IpsOption::NO_MATCH;
}

static IpsOption::EvalStatus rule_28487_eval(void*, Cursor& c, Packet*)
{
    return DetectGdiMemoryCorruption(c, Endian::LITTLE);
}

static SoEvalFunc rule_28487_ctor(const char* /*so*/, void** pv)
{
    *pv = nullptr;
    return rule_28487_eval;
}

static const SoApi so_28487 =
{
    { // base api info
        PT_SO_RULE,
        sizeof(SoApi),
        SOAPI_VERSION,
        4, // version of this file
        API_RESERVED,
        API_OPTIONS,
        "28487", // name
        "OS-WINDOWS Microsoft GDI library TIFF handling memory corruption attempt", // help
        nullptr, // mod_ctor
        nullptr  // mod_dtor
    },
    // so rule api info
    (uint8_t*)rule_28487,
    rule_28487_len,
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    rule_28487_ctor, // ctor
    nullptr  // dtor
};

static IpsOption::EvalStatus rule_28488_eval(void*, Cursor& c, Packet*)
{
    return DetectGdiMemoryCorruption(c, Endian::BIG);
}

static SoEvalFunc rule_28488_ctor(const char* /*so*/, void** pv)
{
    *pv = nullptr;
    return rule_28488_eval;
}

static const SoApi so_28488 =
{
    { // base api info
        PT_SO_RULE,
        sizeof(SoApi),
        SOAPI_VERSION,
        4, // version of this file
        API_RESERVED,
        API_OPTIONS,
        "28488", // name
        "OS-WINDOWS Microsoft GDI library TIFF handling memory corruption attempt", // help
        nullptr,  // mod_ctor
        nullptr   // mod_dtor
    },
    // so rule api info
    (uint8_t*)rule_28488,
    rule_28488_len,
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    rule_28488_ctor, // ctor
    nullptr  // dtor
};

const BaseApi* pso_28487 = &so_28487.base;
const BaseApi* pso_28488 = &so_28488.base;
