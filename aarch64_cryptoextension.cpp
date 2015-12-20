#include <ida.hpp>
#include <idp.hpp>
#include <bytes.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <allins.hpp>

#ifndef __EA64__
#error This extension only makes sense in a 64bit context
#endif

#define MAGIC_ACTIVATED   333
#define MAGIC_DEACTIVATED 777

static ea_t ea;

inline bool is_arm64_ea(ea_t ea)
{
	segment_t *seg = getseg(ea);
	return seg != NULL && seg->use64();
}

#define cond segpref

#define simd_sz specflag1

#define cAL 14

#define Q0 45
#define S0 93
#define V0 163

static size_t ana(void)
{
	uint32_t code = get_long(ea++);
	uint32_t Rn, Rd, Rm;

	if ((code & 0xFFFF0C00) == 0x4E280800) {
		Rn = (code >> 5) & 31;
		Rd = (code) & 31;
		Rd += V0;
		Rn += V0;
		if ((code & 0xF000) == 0x5000) {
			cmd.itype = ARM_aesd;
			cmd.cond = cAL; 
			cmd.Op1.type = o_reg;
			cmd.Op1.simd_sz = 1;
			cmd.Op1.reg = Rd;
			cmd.Op1.dtyp = dt_byte16;
			cmd.Op2.type = o_reg;
			cmd.Op2.simd_sz = 1;
			cmd.Op2.reg = Rn;
			cmd.Op2.dtyp = dt_byte16;
			return 4;
		} else if ((code & 0xF000) == 0x4000) {
			cmd.itype = ARM_aese;
			cmd.cond = cAL; 
			cmd.Op1.type = o_reg;
			cmd.Op1.simd_sz = 1;
			cmd.Op1.reg = Rd;
			cmd.Op1.dtyp = dt_byte16;
			cmd.Op2.type = o_reg;
			cmd.Op2.simd_sz = 1;
			cmd.Op2.reg = Rn;
			cmd.Op2.dtyp = dt_byte16;
			return 4;
		} else if ((code & 0xF000) == 0x7000) {
			cmd.itype = ARM_aesimc;
			cmd.cond = cAL; 
			cmd.Op1.type = o_reg;
			cmd.Op1.simd_sz = 1;
			cmd.Op1.reg = Rd;
			cmd.Op1.dtyp = dt_byte16;
			cmd.Op2.type = o_reg;
			cmd.Op2.simd_sz = 1;
			cmd.Op2.reg = Rn;
			cmd.Op2.dtyp = dt_byte16;
			return 4;
		} else if ((code & 0xF000) == 0x6000) {
			cmd.itype = ARM_aesmc;
			cmd.cond = cAL; 
			cmd.Op1.type = o_reg;
			cmd.Op1.simd_sz = 1;
			cmd.Op1.reg = Rd;
			cmd.Op1.dtyp = dt_byte16;
			cmd.Op2.type = o_reg;
			cmd.Op2.simd_sz = 1;
			cmd.Op2.reg = Rn;
			cmd.Op2.dtyp = dt_byte16;
			return 4;
		}
	} else if ((code & 0xFFE0FC00) == 0x5E000000) {
		Rn = (code >> 5) & 31;
		Rd = (code) & 31;
		Rm = (code >> 16) & 31;
		Rd += Q0;
		Rn += S0;
		Rm += V0;
		cmd.itype = ARM_sha1c;
		cmd.cond = cAL; 
		cmd.Op1.type = o_reg;
		cmd.Op1.reg = Rd;
		cmd.Op1.dtyp = dt_byte16;
		cmd.Op2.type = o_reg;
		cmd.Op2.reg = Rn;
		cmd.Op2.dtyp = dt_dword;
		cmd.Op3.type = o_reg;
		cmd.Op3.simd_sz = 3;
		cmd.Op3.reg = Rm;
		cmd.Op3.dtyp = dt_byte16;
		return 4;
	} else if ((code & 0xFFFFFC00) == 0x5E280800) {
		Rn = (code >> 5) & 31;
		Rd = (code) & 31;
		Rd += S0;
		Rn += S0;
		cmd.itype = ARM_sha1h;
		cmd.cond = cAL; 
		cmd.Op1.type = o_reg;
		cmd.Op1.reg = Rd;
		cmd.Op1.dtyp = dt_dword;
		cmd.Op2.type = o_reg;
		cmd.Op2.reg = Rn;
		cmd.Op2.dtyp = dt_dword;
		return 4;
	} else if ((code & 0xFFE0FC00) == 0x5E002000) {
		Rn = (code >> 5) & 31;
		Rd = (code) & 31;
		Rm = (code >> 16) & 31;
		Rd += Q0;
		Rn += S0;
		Rm += V0;
		cmd.itype = ARM_sha1m;
		cmd.cond = cAL; 
		cmd.Op1.type = o_reg;
		cmd.Op1.reg = Rd;
		cmd.Op1.dtyp = dt_byte16;
		cmd.Op2.type = o_reg;
		cmd.Op2.reg = Rn;
		cmd.Op2.dtyp = dt_dword;
		cmd.Op3.type = o_reg;
		cmd.Op3.simd_sz = 3;
		cmd.Op3.reg = Rm;
		cmd.Op3.dtyp = dt_byte16;
		return 4;
	} else if ((code & 0xFFE0FC00) == 0x5E001000) {
		Rn = (code >> 5) & 31;
		Rd = (code) & 31;
		Rm = (code >> 16) & 31;
		Rd += Q0;
		Rn += S0;
		Rm += V0;
		cmd.itype = ARM_sha1p;
		cmd.cond = cAL; 
		cmd.Op1.type = o_reg;
		cmd.Op1.reg = Rd;
		cmd.Op1.dtyp = dt_byte16;
		cmd.Op2.type = o_reg;
		cmd.Op2.reg = Rn;
		cmd.Op2.dtyp = dt_dword;
		cmd.Op3.type = o_reg;
		cmd.Op3.simd_sz = 3;
		cmd.Op3.reg = Rm;
		cmd.Op3.dtyp = dt_byte16;
		return 4;
	} else if ((code & 0xFFE0FC00) == 0x5E003000) {
		Rn = (code >> 5) & 31;
		Rd = (code) & 31;
		Rm = (code >> 16) & 31;
		Rd += V0;
		Rn += V0;
		Rm += V0;
		cmd.itype = ARM_sha1su0;
		cmd.cond = cAL; 
		cmd.Op1.type = o_reg;
		cmd.Op1.reg = Rd;
		cmd.Op1.simd_sz = 3;
		cmd.Op1.dtyp = dt_byte16;
		cmd.Op2.type = o_reg;
		cmd.Op2.simd_sz = 3;
		cmd.Op2.reg = Rn;
		cmd.Op2.dtyp = dt_byte16;
		cmd.Op3.type = o_reg;
		cmd.Op3.simd_sz = 3;
		cmd.Op3.reg = Rm;
		cmd.Op3.dtyp = dt_byte16;
		return 4;
	} else if ((code & 0xFFFFFC00) == 0x5E281800) {
		Rn = (code >> 5) & 31;
		Rd = (code) & 31;
		Rd += V0;
		Rn += V0;
		cmd.itype = ARM_sha1su1;
		cmd.cond = cAL; 
		cmd.Op1.type = o_reg;
		cmd.Op1.reg = Rd;
		cmd.Op1.simd_sz = 3;
		cmd.Op1.dtyp = dt_byte16;
		cmd.Op2.type = o_reg;
		cmd.Op2.simd_sz = 3;
		cmd.Op2.reg = Rn;
		cmd.Op2.dtyp = dt_byte16;
		return 4;
	} else if ((code & 0xFFE0FC00) == 0x5E005000) {
		Rn = (code >> 5) & 31;
		Rd = (code) & 31;
		Rm = (code >> 16) & 31;
		Rd += Q0;
		Rn += Q0;
		Rm += V0;
		cmd.itype = ARM_sha256h2;
		cmd.cond = cAL; 
		cmd.Op1.type = o_reg;
		cmd.Op1.reg = Rd;
		cmd.Op1.dtyp = dt_byte16;
		cmd.Op2.type = o_reg;
		cmd.Op2.reg = Rn;
		cmd.Op2.dtyp = dt_byte16;
		cmd.Op3.type = o_reg;
		cmd.Op3.simd_sz = 3;
		cmd.Op3.reg = Rm;
		cmd.Op3.dtyp = dt_byte16;
		return 4;
	} else if ((code & 0xFFE0FC00) == 0x5E004000) {
		Rn = (code >> 5) & 31;
		Rd = (code) & 31;
		Rm = (code >> 16) & 31;
		Rd += Q0;
		Rn += Q0;
		Rm += V0;
		cmd.itype = ARM_sha256h;
		cmd.cond = cAL; 
		cmd.Op1.type = o_reg;
		cmd.Op1.reg = Rd;
		cmd.Op1.dtyp = dt_byte16;
		cmd.Op2.type = o_reg;
		cmd.Op2.reg = Rn;
		cmd.Op2.dtyp = dt_byte16;
		cmd.Op3.type = o_reg;
		cmd.Op3.simd_sz = 3;
		cmd.Op3.reg = Rm;
		cmd.Op3.dtyp = dt_byte16;
		return 4;
	} else if ((code & 0xFFFFFC00) == 0x5E282800) {
		Rn = (code >> 5) & 31;
		Rd = (code) & 31;
		Rd += V0;
		Rn += V0;
		cmd.itype = ARM_sha256su0;
		cmd.cond = cAL; 
		cmd.Op1.type = o_reg;
		cmd.Op1.reg = Rd;
		cmd.Op1.simd_sz = 3;
		cmd.Op1.dtyp = dt_byte16;
		cmd.Op2.type = o_reg;
		cmd.Op2.simd_sz = 3;
		cmd.Op2.reg = Rn;
		cmd.Op2.dtyp = dt_byte16;
		return 4;
	} else if ((code & 0xFFE0FC00) == 0x5E006000) {
		Rn = (code >> 5) & 31;
		Rd = (code) & 31;
		Rm = (code >> 16) & 31;
		Rd += V0;
		Rn += V0;
		Rm += V0;
		cmd.itype = ARM_sha256su1;
		cmd.cond = cAL; 
		cmd.Op1.type = o_reg;
		cmd.Op1.reg = Rd;
		cmd.Op1.simd_sz = 3;
		cmd.Op1.dtyp = dt_byte16;
		cmd.Op2.type = o_reg;
		cmd.Op2.simd_sz = 3;
		cmd.Op2.reg = Rn;
		cmd.Op2.dtyp = dt_byte16;
		cmd.Op3.type = o_reg;
		cmd.Op3.simd_sz = 3;
		cmd.Op3.reg = Rm;
		cmd.Op3.dtyp = dt_byte16;
		return 4;
	}
	return 0;
}

static int idaapi aarch64_extension_callback(void * user_data, int event_id, va_list va)
{
	switch (event_id)
	{
		case processor_t::custom_ana:
		{
			ea = cmd.ea;
			if (is_arm64_ea(ea)) {
				size_t length = ana();
				if (length)
				{
					cmd.size = (uint16)length;
					return 2;
				}
			}
		}
		break;
	}
	return 0;
}

static bool enabled = false;
static netnode aarch64_node;
static const char node_name[] = "$ AArch64 crypto extension processor extender parameters";

int idaapi init(void)
{
	if (ph.id != PLFM_ARM) return PLUGIN_SKIP;
	aarch64_node.create(node_name);
	enabled = aarch64_node.altval(0) != MAGIC_DEACTIVATED;
	if (enabled)
	{
		hook_to_notification_point(HT_IDP, aarch64_extension_callback, NULL);
		msg("AArch64 crypto extension processor extender is enabled\n");
		return PLUGIN_KEEP;
	}
	return PLUGIN_OK;
}


void idaapi term(void)
{
	unhook_from_notification_point(HT_IDP, aarch64_extension_callback);
}

void idaapi run(int /*arg*/)
{
	if (enabled) {
		unhook_from_notification_point(HT_IDP, aarch64_extension_callback);
	} else {
		hook_to_notification_point(HT_IDP, aarch64_extension_callback, NULL);
	}
	enabled = !enabled;
	aarch64_node.create(node_name);
	aarch64_node.altset(0, enabled ? MAGIC_ACTIVATED : MAGIC_DEACTIVATED);
	info("AUTOHIDE NONE\n" "AArch64 crypto extension processor extender now is %s", enabled ? "enabled" : "disabled");
}

//--------------------------------------------------------------------------
static const char comment[] = "AArch64 crypto extension processor extender";
static const char help[] = "This module adds support for AArch64 crypto extension instructions to IDA.\n";

static const char wanted_name[] = "AArch64 crypto extension processor extender";

static const char wanted_hotkey[] = "";

plugin_t PLUGIN =
{
	IDP_INTERFACE_VERSION,
	PLUGIN_PROC,
	init,
	term,
	run,
	comment,
	help,
	wanted_name,
	wanted_hotkey
};
