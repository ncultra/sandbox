#define _LARGEFILE64_SOURCE
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <openssl/sha.h>

#include "util.h"
#include "patch_file.h"

#include "R100_cp.firmware.h"


/*
 * Note about addresses. This program deals in four different views of
 * of addresses:
 * 1) Virtual address of this process [laddr]
 * 2) Virtual address of hypervisor [haddr]
 * 3) Physical address (also known as bus address) [paddr]
 * 4) Graphics address (mostly physical, but some virtual) [gaddr]
 */

struct tablepatch {
    char *tablename;
    uint64_t hvabs;
    uint16_t datalen;
    unsigned char *data;
};


#define __HYPERVISOR_arch_2	50


/* Memory barrier */
#define wb()	asm volatile ("" : : : "memory")


/* Flags field in /sys/bus/pci/<device id>/resource file */
/* These flags aren't a stable kernel ABI. It has changed. Modern kernels
 * define 5-bits for the type, but older kernels (like the ones installed
 * by XS dom0) are 4-bits. We don't need the extra types */
#define IORESOURCE_TYPE_BITS    0x00000f00      /* Resource type */
#define IORESOURCE_IO           0x00000100      /* PCI/ISA I/O ports */
#define IORESOURCE_MEM          0x00000200
#define IORESOURCE_REG          0x00000300      /* Register offsets */
#define IORESOURCE_IRQ          0x00000400
#define IORESOURCE_DMA          0x00000800

#define IORESOURCE_READONLY     0x00004000


#define RADEON_USEC_TIMEOUT		100000L

#define REG_SET(FIELD, v)		(((v) << FIELD##_SHIFT) & FIELD##_MASK)


#define RADEON_CLOCK_CNTL_INDEX		0x0008
#define RADEON_CLOCK_CNTL_DATA		0x000c
#define   RADEON_PLL_WR_EN		(1 << 7)
#define   RADEON_PLL_DIV_SEL		(3 << 8)
#define   RADEON_PLL2_DIV_SEL_MASK	(~(3 << 8))

#define R_00000D_SCLK_CNTL		0x00000d
#define   S_00000D_SCLK_SRC_SEL(x)	(((x) & 0x7) << 0)
#define   G_00000D_SCLK_SRC_SEL(x)	(((x) >> 0) & 0x7)
#define   C_00000D_SCLK_SRC_SEL		0xFFFFFFF8
#define   S_00000D_TCLK_SRC_SEL(x)	(((x) & 0x7) << 8)
#define   G_00000D_TCLK_SRC_SEL(x)	(((x) >> 8) & 0x7)
#define   C_00000D_TCLK_SRC_SEL		0xFFFFF8FF
#define   S_00000D_FORCE_DISP2(x)	(((x) & 0x1) << 15)
#define   G_00000D_FORCE_DISP2(x)	(((x) >> 15) & 0x1)
#define   C_00000D_FORCE_DISP2		0xFFFF7FFF
#define   S_00000D_FORCE_CP(x)		(((x) & 0x1) << 16)
#define   G_00000D_FORCE_CP(x)		(((x) >> 16) & 0x1)
#define   C_00000D_FORCE_CP		0xFFFEFFFF
#define   S_00000D_FORCE_HDP(x)		(((x) & 0x1) << 17)
#define   G_00000D_FORCE_HDP(x)		(((x) >> 17) & 0x1)
#define   C_00000D_FORCE_HDP		0xFFFDFFFF
#define   S_00000D_FORCE_DISP(x)	(((x) & 0x1) << 18)
#define   G_00000D_FORCE_DISP(x)	(((x) >> 18) & 0x1)
#define   C_00000D_FORCE_DISP		0xFFFBFFFF
#define   S_00000D_FORCE_DISP1(x)	(((x) & 0x1) << 18)
#define   G_00000D_FORCE_DISP1(x)	(((x) >> 18) & 0x1)
#define   C_00000D_FORCE_DISP1		0xFFFBFFFF
#define   S_00000D_FORCE_TOP(x)		(((x) & 0x1) << 19)
#define   G_00000D_FORCE_TOP(x)		(((x) >> 19) & 0x1)
#define   C_00000D_FORCE_TOP		0xFFF7FFFF
#define   S_00000D_FORCE_E2(x)		(((x) & 0x1) << 20)
#define   G_00000D_FORCE_E2(x)		(((x) >> 20) & 0x1)
#define   C_00000D_FORCE_E2		0xFFEFFFFF
#define   S_00000D_FORCE_SE(x)		(((x) & 0x1) << 21)
#define   G_00000D_FORCE_SE(x)		(((x) >> 21) & 0x1)
#define   C_00000D_FORCE_SE		0xFFDFFFFF
#define   S_00000D_FORCE_IDCT(x)	(((x) & 0x1) << 22)
#define   G_00000D_FORCE_IDCT(x)	(((x) >> 22) & 0x1)
#define   C_00000D_FORCE_IDCT		0xFFBFFFFF
#define   S_00000D_FORCE_VIP(x)		(((x) & 0x1) << 23)
#define   G_00000D_FORCE_VIP(x)		(((x) >> 23) & 0x1)
#define   C_00000D_FORCE_VIP		0xFF7FFFFF
#define   S_00000D_FORCE_RE(x)		(((x) & 0x1) << 24)
#define   G_00000D_FORCE_RE(x)		(((x) >> 24) & 0x1)
#define   C_00000D_FORCE_RE		0xFEFFFFFF
#define   S_00000D_FORCE_PB(x)		(((x) & 0x1) << 25)
#define   G_00000D_FORCE_PB(x)		(((x) >> 25) & 0x1)
#define   C_00000D_FORCE_PB		0xFDFFFFFF
#define   S_00000D_FORCE_TAM(x)		(((x) & 0x1) << 26)
#define   G_00000D_FORCE_TAM(x)		(((x) >> 26) & 0x1)
#define   C_00000D_FORCE_TAM		0xFBFFFFFF
#define   S_00000D_FORCE_TDM(x)		(((x) & 0x1) << 27)
#define   G_00000D_FORCE_TDM(x)		(((x) >> 27) & 0x1)
#define   C_00000D_FORCE_TDM		0xF7FFFFFF
#define   S_00000D_FORCE_RB(x)		(((x) & 0x1) << 28)
#define   G_00000D_FORCE_RB(x)		(((x) >> 28) & 0x1)
#define   C_00000D_FORCE_RB		0xEFFFFFFF



#define RADEON_BUS_CNTL			0x0030
#define RADEON_BUS_MASTER_DIS		(1 << 6)

#define R_0000F0_RBBM_SOFT_RESET	0x0000F0
#define   S_0000F0_SOFT_RESET_CP(x)	(((x) & 0x1) << 0)
#define   G_0000F0_SOFT_RESET_CP(x)	(((x) >> 0) & 0x1)
#define   C_0000F0_SOFT_RESET_CP	0xFFFFFFFE
#define   S_0000F0_SOFT_RESET_SE(x)	(((x) & 0x1) << 2)
#define   G_0000F0_SOFT_RESET_SE(x)	(((x) >> 2) & 0x1)
#define   C_0000F0_SOFT_RESET_SE	0xFFFFFFFB
#define   S_0000F0_SOFT_RESET_RE(x)	(((x) & 0x1) << 3)
#define   G_0000F0_SOFT_RESET_RE(x)	(((x) >> 3) & 0x1)
#define   C_0000F0_SOFT_RESET_RE	0xFFFFFFF7
#define   S_0000F0_SOFT_RESET_PP(x)	(((x) & 0x1) << 4)
#define   G_0000F0_SOFT_RESET_PP(x)	(((x) >> 4) & 0x1)
#define   C_0000F0_SOFT_RESET_PP	0xFFFFFFEF
#define   S_0000F0_SOFT_RESET_RB(x)	(((x) & 0x1) << 6)
#define   G_0000F0_SOFT_RESET_RB(x)	(((x) >> 6) & 0x1)
#define   C_0000F0_SOFT_RESET_RB	0xFFFFFFBF

#define RADEON_CONFIG_MEMSIZE		0x00f8

#define RADEON_MC_FB_LOCATION		0x000148

#define R_00014C_MC_AGP_LOCATION	0x00014c
#define   S_00014C_MC_AGP_START(x)	(((x) & 0xFFFF) << 0)
#define   G_00014C_MC_AGP_START(x)	(((x) >> 0) & 0xFFFF)
#define   C_00014C_MC_AGP_START		0xFFFF0000
#define   S_00014C_MC_AGP_TOP(x)	(((x) & 0xFFFF) << 16)
#define   G_00014C_MC_AGP_TOP(x)	(((x) >> 16) & 0xFFFF)
#define   C_00014C_MC_AGP_TOP		0x0000FFFF
#define R_000170_AGP_BASE		0x000170
#define   S_000170_AGP_BASE_ADDR(x)	(((x) & 0xFFFFFFFF) << 0)
#define   G_000170_AGP_BASE_ADDR(x)	(((x) >> 0) & 0xFFFFFFFF)
#define   C_000170_AGP_BASE_ADDR	0x00000000

#define RADEON_AIC_CNTL				0x01d0
#define   RADEON_PCIGART_TRANSLATE_EN		(1 << 0)
#define   RADEON_DIS_OUT_OF_PCI_GART_ACCESS	(1 << 1)
#define RADEON_AIC_STAT				0x01d4
#define RADEON_AIC_PT_BASE			0x01d8
#define RADEON_AIC_LO_ADDR			0x01dc
#define RADEON_AIC_HI_ADDR			0x01e0
#define RADEON_AIC_TLB_ADDR			0x01e4
#define RADEON_AIC_TLB_DATA			0x01e8

#define R_0003C2_GENMO_WT			0x0003C2
#define   S_0003C2_VGA_RAM_EN(x)		(((x) & 0x1) << 1)
#define   G_0003C2_VGA_RAM_EN(x)		(((x) >> 1) & 0x1)
#define   C_0003C2_VGA_RAM_EN			0xFD

#define RADEON_CP_RB_BASE			0x0700
#define RADEON_CP_RB_CNTL			0x0704
#define   RADEON_RB_BUFSZ_SHIFT			0
#define   RADEON_RB_BUFSZ_MASK			(0x3f << 0)
#define   RADEON_RB_BLKSZ_SHIFT			8
#define   RADEON_RB_BLKSZ_MASK			(0x3f << 8)
#define   RADEON_BUF_SWAP_32BIT			(2 << 16)
#define   RADEON_MAX_FETCH_SHIFT		18
#define   RADEON_MAX_FETCH_MASK			(0x3 << 18)
#define   RADEON_RB_NO_UPDATE			(1 << 27)
#define   RADEON_RB_RPTR_WR_ENA			(1 << 31)

#define RADEON_CP_RB_RPTR_ADDR			0x070c
#define RADEON_CP_RB_RPTR			0x0710
#define RADEON_CP_RB_WPTR			0x0714
#define RADEON_CP_RB_WPTR_DELAY			0x0718
#define RADEON_CP_RB_RPTR_WR			0x071c


#define RADEON_CP_CSQ_CNTL			0x0740
#define   RADEON_CSQ_CNT_PRIMARY_MASK		(0xff << 0)
#define   RADEON_CSQ_PRIDIS_INDDIS		(0    << 28)
#define   RADEON_CSQ_PRIPIO_INDDIS		(1    << 28)
#define   RADEON_CSQ_PRIBM_INDDIS		(2    << 28)
#define   RADEON_CSQ_PRIPIO_INDBM		(3    << 28)
#define   RADEON_CSQ_PRIBM_INDBM		(4    << 28)
#define   RADEON_CSQ_PRIPIO_INDPIO		(15   << 28)
#define RADEON_CP_CSQ_MODE			0x0744


#define RADEON_SCRATCH_UMSK			0x0770


#define RADEON_CP_ME_RAM_ADDR			0x07d4
#define RADEON_CP_ME_RAM_RADDR			0x07d8
#define RADEON_CP_ME_RAM_DATAH			0x07dc
#define RADEON_CP_ME_RAM_DATAL			0x07e0


#define RADEON_RBBM_STATUS			0x0e40
#define   RBBM_STATUS_CP_BUSY_SHIFT		16
#define   RBBM_STATUS_CP_BUSY_MASK		(1 << 16)
#define   RBBM_STATUS_SE_BUSY_SHIFT		20
#define   RBBM_STATUS_SE_BUSY_MASK		(1 << 20)
#define   RBBM_STATUS_RE_BUSY_SHIFT		21
#define   RBBM_STATUS_RE_BUSY_MASK		(1 << 21)
#define   RBBM_STATUS_TAM_BUSY_SHIFT		22
#define   RBBM_STATUS_TAM_BUSY_MASK		(1 << 22)
#define   RBBM_STATUS_PB_BUSY_SHIFT		24
#define   RBBM_STATUS_PB_BUSY_MASK		(1 << 24)
#define   RBBM_STATUS_GUI_ACTIVE_SHIFT		31
#define   RBBM_STATUS_GUI_ACTIVE_MASK		(1 << 31)


#define RADEON_SCRATCH_REG0			0x15e0


#define RADEON_DSTCACHE_CTLSTAT			0x1714

#define RADEON_WAIT_UNTIL			0x1720
#define   RADEON_WAIT_CRTC_PFLIP		(1 << 0)
#define   RADEON_WAIT_RE_CRTC_VLINE		(1 << 1)
#define   RADEON_WAIT_FE_CRTC_VLINE		(1 << 2)
#define   RADEON_WAIT_CRTC_VLINE		(1 << 3)
#define   RADEON_WAIT_DMA_VID_IDLE		(1 << 8)
#define   RADEON_WAIT_DMA_GUI_IDLE		(1 << 9)
#define   RADEON_WAIT_CMDFIFO			(1 << 10)
#define   RADEON_WAIT_OV0_FLIP			(1 << 11)
#define   RADEON_WAIT_AGP_FLUSH			(1 << 13)
#define   RADEON_WAIT_2D_IDLE			(1 << 14)
#define   RADEON_WAIT_3D_IDLE			(1 << 15)
#define   RADEON_WAIT_2D_IDLECLEAN		(1 << 16)
#define   RADEON_WAIT_3D_IDLECLEAN		(1 << 17)
#define   RADEON_WAIT_HOST_IDLECLEAN		(1 << 18)
#define   RADEON_CMDFIFO_ENTRIES_SHIFT		10
#define   RADEON_CMDFIFO_ENTRIES_MASK		0x7f
#define   RADEON_WAIT_VAP_IDLE			(1 << 28)
#define   RADEON_WAIT_BOTH_CRTC_PFLIP		(1 << 30)
#define   RADEON_ENG_DISPLAY_SELECT_CRTC0	(0 << 31)
#define   RADEON_ENG_DISPLAY_SELECT_CRTC1	(1 << 31)


#define RADEON_ISYNC_CNTL			0x1724
#define   RADEON_ISYNC_ANY2D_IDLE3D		(1 << 0)
#define   RADEON_ISYNC_ANY3D_IDLE2D		(1 << 1)
#define   RADEON_ISYNC_TRIG2D_IDLE3D		(1 << 2)
#define   RADEON_ISYNC_TRIG3D_IDLE2D		(1 << 3)
#define   RADEON_ISYNC_WAIT_IDLEGUI		(1 << 4)
#define   RADEON_ISYNC_CPSCRATCH_IDLEGUI	(1 << 5)

#define RADEON_RB2D_DSTCACHE_CTLSTAT		0x342c
#define   RADEON_RB2D_DC_FLUSH			(3 << 0)
#define   RADEON_RB2D_DC_FREE			(3 << 2)
#define   RADEON_RB2D_DC_FLUSH_ALL		0xf
#define   RADEON_RB2D_DC_BUSY			(1 << 31)


#define RADEON_CP_PACKET0			0x00000000
#define   PACKET0_BASE_INDEX_SHIFT		0
#define   PACKET0_BASE_INDEX_MASK		(0x1ffff << 0)
#define   PACKET0_COUNT_SHIFT			16
#define   PACKET0_COUNT_MASK			(0x3fff << 16)

#define RADEON_CP_PACKET3			0xC0000000
#define   PACKET3_IT_OPCODE_SHIFT		8
#define   PACKET3_IT_OPCODE_MASK		(0xff << 8)
#define   PACKET3_COUNT_SHIFT			16
#define   PACKET3_COUNT_MASK			(0x3fff << 16)

#define   PACKET3_NOP				0x10
#define   PACKET3_BITBLT_MULTI			0x9B

#define     RADEON_GMC_SRC_PITCH_OFFSET_CNTL	(1    <<  0)
#define     RADEON_GMC_DST_PITCH_OFFSET_CNTL	(1    <<  1)
#define     RADEON_GMC_SRC_CLIPPING		(1    <<  2)
#define     RADEON_GMC_DST_CLIPPING		(1    <<  3)
#define     RADEON_GMC_BRUSH_DATATYPE_MASK	(0x0f <<  4)
#define     RADEON_GMC_BRUSH_8X8_MONO_FG_BG	(0    <<  4)
#define     RADEON_GMC_BRUSH_8X8_MONO_FG_LA	(1    <<  4)
#define     RADEON_GMC_BRUSH_1X8_MONO_FG_BG	(4    <<  4)
#define     RADEON_GMC_BRUSH_1X8_MONO_FG_LA	(5    <<  4)
#define     RADEON_GMC_BRUSH_32x1_MONO_FG_BG	(6    <<  4)
#define     RADEON_GMC_BRUSH_32x1_MONO_FG_LA	(7    <<  4)
#define     RADEON_GMC_BRUSH_32x32_MONO_FG_BG	(8    <<  4)
#define     RADEON_GMC_BRUSH_32x32_MONO_FG_LA	(9    <<  4)
#define     RADEON_GMC_BRUSH_8x8_COLOR		(10   <<  4)
#define     RADEON_GMC_BRUSH_1X8_COLOR		(12   <<  4)
#define     RADEON_GMC_BRUSH_SOLID_COLOR	(13   <<  4)
#define     RADEON_GMC_BRUSH_NONE		(15   <<  4)
#define     RADEON_GMC_DST_8BPP_CI		(2    <<  8)
#define     RADEON_GMC_DST_15BPP		(3    <<  8)
#define     RADEON_GMC_DST_16BPP		(4    <<  8)
#define     RADEON_GMC_DST_24BPP		(5    <<  8)
#define     RADEON_GMC_DST_32BPP		(6    <<  8)
#define     RADEON_GMC_DST_8BPP_RGB		(7    <<  8)
#define     RADEON_GMC_DST_Y8			(8    <<  8)
#define     RADEON_GMC_DST_RGB8			(9    <<  8)
#define     RADEON_GMC_DST_VYUY			(11   <<  8)
#define     RADEON_GMC_DST_YVYU			(12   <<  8)
#define     RADEON_GMC_DST_AYUV444		(14   <<  8)
#define     RADEON_GMC_DST_ARGB4444		(15   <<  8)
#define     RADEON_GMC_DST_DATATYPE_MASK	(0x0f <<  8)
#define     RADEON_GMC_DST_DATATYPE_SHIFT	8
#define     RADEON_GMC_SRC_DATATYPE_MASK	(3    << 12)
#define     RADEON_GMC_SRC_DATATYPE_MONO_FG_BG	(0    << 12)
#define     RADEON_GMC_SRC_DATATYPE_MONO_FG_LA	(1    << 12)
#define     RADEON_GMC_SRC_DATATYPE_COLOR	(3    << 12)
#define     RADEON_GMC_BYTE_PIX_ORDER		(1    << 14)
#define     RADEON_GMC_BYTE_MSB_TO_LSB		(0    << 14)
#define     RADEON_GMC_BYTE_LSB_TO_MSB		(1    << 14)
#define     RADEON_GMC_CONVERSION_TEMP		(1    << 15)
#define     RADEON_GMC_CONVERSION_TEMP_6500	(0    << 15)
#define     RADEON_GMC_CONVERSION_TEMP_9300	(1    << 15)
#define     RADEON_GMC_ROP3_MASK		(0xff << 16)
#define     RADEON_DP_SRC_SOURCE_MASK		(7    << 24)
#define     RADEON_DP_SRC_SOURCE_MEMORY		(2    << 24)
#define     RADEON_DP_SRC_SOURCE_HOST_DATA	(3    << 24)
#define     RADEON_GMC_3D_FCN_EN		(1    << 27)
#define     RADEON_GMC_CLR_CMP_CNTL_DIS		(1    << 28)
#define     RADEON_GMC_AUX_CLIP_DIS		(1    << 29)
#define     RADEON_GMC_WR_MSK_DIS		(1    << 30)
#define     RADEON_GMC_LD_BRUSH_Y_X		(1    << 31)
#define     RADEON_ROP3_ZERO			0x00000000
#define     RADEON_ROP3_DSa			0x00880000
#define     RADEON_ROP3_SDna			0x00440000
#define     RADEON_ROP3_S			0x00cc0000
#define     RADEON_ROP3_DSna			0x00220000
#define     RADEON_ROP3_D			0x00aa0000
#define     RADEON_ROP3_DSx			0x00660000
#define     RADEON_ROP3_DSo			0x00ee0000
#define     RADEON_ROP3_DSon			0x00110000
#define     RADEON_ROP3_DSxn			0x00990000
#define     RADEON_ROP3_Dn			0x00550000
#define     RADEON_ROP3_SDno			0x00dd0000
#define     RADEON_ROP3_Sn			0x00330000
#define     RADEON_ROP3_DSno			0x00bb0000
#define     RADEON_ROP3_DSan			0x00770000
#define     RADEON_ROP3_ONE			0x00ff0000
#define     RADEON_ROP3_DPa			0x00a00000
#define     RADEON_ROP3_PDna			0x00500000
#define     RADEON_ROP3_P			0x00f00000
#define     RADEON_ROP3_DPna			0x000a0000
#define     RADEON_ROP3_DPx			0x005a0000
#define     RADEON_ROP3_DPo			0x00fa0000
#define     RADEON_ROP3_DPon			0x00050000
#define     RADEON_ROP3_PDxn			0x00a50000
#define     RADEON_ROP3_PDno			0x00f50000
#define     RADEON_ROP3_Pn			0x000f0000
#define     RADEON_ROP3_DPno			0x00af0000
#define     RADEON_ROP3_DPan			0x005f0000

#define   RADEON_COLOR_FORMAT_ARGB1555		3
#define   RADEON_COLOR_FORMAT_RGB565		4
#define   RADEON_COLOR_FORMAT_ARGB8888		6
#define   RADEON_COLOR_FORMAT_RGB332		7
#define   RADEON_COLOR_FORMAT_Y8		8
#define   RADEON_COLOR_FORMAT_RGB8		9
#define   RADEON_COLOR_FORMAT_YUV422_VYUY	11
#define   RADEON_COLOR_FORMAT_YUV422_YVYU	12
#define   RADEON_COLOR_FORMAT_aYUV444		14
#define   RADEON_COLOR_FORMAT_ARGB4444		15


#define PACKET0(reg, n)	(RADEON_CP_PACKET0 | \
			 REG_SET(PACKET0_BASE_INDEX, ((reg) >> 2)) | \
			 REG_SET(PACKET0_COUNT, (n)))
#define PACKET3(op, n)	(RADEON_CP_PACKET3 | \
			 REG_SET(PACKET3_IT_OPCODE, (op)) | \
			 REG_SET(PACKET3_COUNT, (n)))


#define ADDRING(v)	\
	do { \
	    radeon.ring[radeon.wptr++] = (v); \
	    if (radeon.wptr >= radeon.ring_entries) \
	        radeon.wptr = 0; \
	} while(0)


struct resource {
    int num;
    uint32_t start;
    size_t size;
};

struct radeon {
    struct resource mmiores;
    volatile unsigned char *mmio;
    size_t mmio_size;

    struct resource vramres;
    volatile unsigned char *vram;
    size_t vram_size;

    /* Page Table */
    volatile uint32_t *pt;
    void *dummy;

    /* GTT */
    uint32_t gtt_start;
    uint32_t gtt_end;

    /* Ring Buffer for CP */
    volatile uint32_t *ring;
    unsigned int wptr;
    unsigned int ring_entries;
};


static struct radeon radeon;


int order_base_2(int n)
{
    int ret = 0;
    while (!(n & 1)) {
        ret++;
        n >>= 1;
    }

    return ret;
}


#define PAGE_SHIFT 12
#define PAGEMAP_LENGTH 8

uint64_t get_physical_address(volatile void *ptr)
{
    char *filepath = "/proc/self/pagemap";
    unsigned long laddr = (unsigned long)ptr;

    int fd = open(filepath, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "error: open(%s): %m\n", filepath);
        exit(1);
    }

    off64_t offset = laddr / getpagesize() * PAGEMAP_LENGTH;
    off_t ret = lseek64(fd, offset, SEEK_SET);
    if (ret == (off_t)-1) {
        fprintf(stderr, "error: lseek(%s, %Zd): %m\n", filepath, offset);
        exit(1);
    }
    if (ret != offset) {
        fprintf(stderr, "error: tried to seek to %Zd, but only got to %Zd\n",
                offset, ret);
        exit(1);
    }

    uint64_t pfn = 0;
    if (read(fd, &pfn, PAGEMAP_LENGTH) != PAGEMAP_LENGTH) {
        fprintf(stderr, "error: read(%s, %d): %m\n",
                filepath, PAGEMAP_LENGTH);
        exit(1);
    }
    close(fd);

    pfn &= 0x7FFFFFFFFFFFFFLL;

    uint64_t paddr = pfn << PAGE_SHIFT;
    paddr |= ((unsigned long)laddr & ~4095);

    /* Sanity check */
    if (paddr & ~((1ULL << 32) - 1)) {
        fprintf(stderr, "error: physical address outside of "
                "32-bit range (%llx)\n", paddr);
        exit(1);
    }

    return paddr;
}


uint8_t read8(size_t offset)
{
    return *(volatile uint8_t *)((unsigned char *)radeon.mmio + offset);
}


uint32_t read32(size_t offset)
{
    return *(volatile uint32_t *)((unsigned char *)radeon.mmio + offset);
}


void write8(size_t offset, uint8_t value)
{
    *(radeon.mmio + offset) = value;
}


void write32(size_t offset, uint32_t value)
{
    *(volatile uint32_t *)((unsigned char *)radeon.mmio + offset) = value;
}


int usec_diff(struct timeval a, struct timeval b)
{
    int ret;
    if (a.tv_usec > b.tv_usec)
        ret = b.tv_usec - (1000000 - a.tv_usec);
    else
        ret = b.tv_usec - a.tv_usec;

    ret += (b.tv_sec - a.tv_sec) * 1000000;
    return ret;
}


void wait_for_idle(unsigned int bit)
{
    uint32_t tmp;
    struct timeval start;

    gettimeofday(&start, NULL);
    while (1) {
        tmp = read32(RADEON_RBBM_STATUS);
        if (!(tmp & bit))
            return;

        struct timeval now;
        gettimeofday(&now, NULL);
        if (usec_diff(start, now) >= RADEON_USEC_TIMEOUT)
            break;

        usleep(1);
    }

    fprintf(stderr, "error: timeout waiting for CP to be idle %x\n", tmp);
    exit(1);
}


void *align_malloc(size_t size)
{
    void *ptr = malloc(size + 4095);
    if (!ptr) {
        fprintf(stderr, "error: malloc(%d): %m\n", size + 4095);
        exit(1);
    }

    /* Lock buffer into memory */
    if (mlock(ptr, size + 4095) < 0) {
        fprintf(stderr, "error: mlock: %m\n");
        exit(1);
    }

    /* Side-effect will check that address resides in 32-bit space */
    get_physical_address(ptr);

    /* Page-align address returned */
    unsigned long laddr = (unsigned long)ptr;
    if (laddr & 4095)
        laddr += 4096 - (laddr & 4095);

    return (void *)laddr;
}


int wait_for_scratch_reg(uint32_t value)
{
    uint32_t tmp;
    struct timeval start;

    gettimeofday(&start, NULL);
    while (1) {
        tmp = read32(RADEON_SCRATCH_REG0);
        if (tmp == value)
            return 0;

        struct timeval now;
        gettimeofday(&now, NULL);
        if (usec_diff(start, now) >= RADEON_USEC_TIMEOUT)
            break;

        usleep(1);
    }

    printf("error: timeout waiting for scratch reg "
           "(expected = 0x%x, tmp = 0x%x)\n",
           value, tmp);

    return -1;
}


/* FIXME: Code only copies 1k-aligned addresses right now */
int copy_mem(uint32_t src_gaddr, size_t size, uint32_t dst_gaddr)
{
    int num_gpu_pages = (size + 4095) / 4096;
    int cur_pages = num_gpu_pages;
    /* Setup stride and pitch so we copy exactly one contiguous page */
    uint32_t stride_bytes = 4096;
    uint32_t stride_pixels = stride_bytes / 4;
    uint32_t pitch = stride_bytes / 64;

    ADDRING(PACKET3(PACKET3_BITBLT_MULTI, 8));
    ADDRING(RADEON_GMC_SRC_PITCH_OFFSET_CNTL |
            RADEON_GMC_DST_PITCH_OFFSET_CNTL |
            RADEON_GMC_SRC_CLIPPING |
            RADEON_GMC_DST_CLIPPING |
            RADEON_GMC_BRUSH_NONE |
            (RADEON_COLOR_FORMAT_ARGB8888 << 8) |
            RADEON_GMC_SRC_DATATYPE_COLOR |
            RADEON_ROP3_S |
            RADEON_DP_SRC_SOURCE_MEMORY |
            RADEON_GMC_CLR_CMP_CNTL_DIS |
            RADEON_GMC_WR_MSK_DIS);

    /* SETTINGS */

    /* SRC_PITCH_OFFSET */
    ADDRING((pitch << 22) | (src_gaddr >> 10));
    /* DST_PITCH_OFFSET */
    ADDRING((pitch << 22) | (dst_gaddr >> 10));
    /* SRC_CLIPPING */
    ADDRING((0x1fff << 16) | 0x1fff);
    /* DST_CLIPPING */
    ADDRING(0);				/* Top Left */
    ADDRING((0x1fff << 16) | 0x1fff);	/* Bottom Right */

    /* DATA_BLOCK */

    ADDRING(0);				/* Src Top Left */
    ADDRING(0);				/* Dst Top Left */
    /* Width == 4096 bytes, Height == num pages */
    ADDRING((stride_pixels << 16) | num_gpu_pages);	/* Width Height */

    /* Flush out */
    ADDRING(PACKET0(RADEON_DSTCACHE_CTLSTAT, 0));
    ADDRING(RADEON_RB2D_DC_FLUSH_ALL);

    /* Wait for idle */
    ADDRING(PACKET0(RADEON_WAIT_UNTIL, 0));
    ADDRING(RADEON_WAIT_2D_IDLECLEAN |
            RADEON_WAIT_HOST_IDLECLEAN |
            RADEON_WAIT_DMA_GUI_IDLE);

    /* Emit fence sequence */
    write32(RADEON_SCRATCH_REG0, 0);

    /* Insert Type-0 packet to write to scratch register */
    ADDRING(PACKET0(RADEON_SCRATCH_REG0, 0));
    ADDRING(1);

    /* Commit */
    wb();
    write32(RADEON_CP_RB_WPTR, radeon.wptr);
    read32(RADEON_CP_RB_WPTR);

    if (wait_for_scratch_reg(1) < 0)
        return -1;

    return 0;
}


void *copy_from(uint32_t src_paddr, size_t size, uint32_t dst_offset)
{
    uint32_t dst_gaddr = radeon.vramres.start + dst_offset;

    /* Need to read/write on 1k aligned locations, so adjust */
    uint32_t src_offset = src_paddr & 1023;
    src_paddr -= src_offset;
    size += src_offset;

    memset((unsigned char *)radeon.vram + dst_offset, 0, size);

#if 0
    /* GTT method doesn't seem to work */
    radeon.pt[0] = src_paddr;
    if (copy_mem(radeon.gtt_start, size, dst_gaddr) < 0)
#else
    if (copy_mem(src_paddr, size, dst_gaddr) < 0)
#endif
        return NULL;

    return (unsigned char *)radeon.vram + dst_offset + src_offset;
}


int copy_to(uint32_t src_offset, size_t size, uint32_t dst_paddr)
{
    uint32_t src_gaddr = radeon.vramres.start + src_offset;

#if 0
    /* GTT method doesn't seem to work */
    radeon.pt[0] = dst_paddr;
    return copy_mem(src_gaddr, size, radeon.gtt_start);
#else
    return copy_mem(src_gaddr, size, dst_paddr);
#endif
}


void hex_dump(void *ptr, size_t size)
{
    unsigned char *buf = ptr;
    size_t i;

    for (i = 0; i < size; i += 16) {
        printf("%04x:", i);

        size_t j;
        for (j = 0; j < 16 && i + j < size; j++)
            printf(" %02x", buf[i + j]);

        printf("  ");

        for (j = 0; j < 16 && i + j < size; j++) {
            unsigned char c = buf[i + j];
            if (isprint(c) && !isspace(c))
                printf("%c", c);
            else
                printf(" ");
        }

        printf("\n");
    }
}


int read_hex16(char *filepath, uint16_t *value)
{
    FILE *f = fopen(filepath, "r");
    if (!f) {
        fprintf(stderr, "warn: fopen(%s): %m\n", filepath);
        return -1;
    }

    unsigned int v;
    int ret = fscanf(f, "0x%04x\n", &v);
    fclose(f);

    if (ret != 1) {
        fprintf(stderr, "warn: %s: could not scan 16-bit hex value\n",
                filepath);
        return -1;
    }

    *value = v;

    return 0;
}


int read_hex64(char *filepath, uint64_t *value)
{
    FILE *f = fopen(filepath, "r");
    if (!f) {
        fprintf(stderr, "error: fopen(%s): %m\n", filepath);
        return -1;
    }

    unsigned long long v;
    int ret = fscanf(f, "0x%llx\n", &v);
    fclose(f);

    if (ret != 1) {
        fprintf(stderr, "error: %s: could not scan 64-bit hex value\n",
                filepath);
        return -1;
    }

    *value = v;

    return 0;
}


int find_device(char *basedir, char *devicepath, size_t devicepathsize)
{
    DIR *dir;
    struct dirent *dirent;

    dir = opendir(basedir);
    if (!dir) {
        fprintf(stderr, "error: opendir(%s): %m\n", basedir);
        return -1;
    }

    while ((dirent = readdir(dir)) != NULL) {
        if (dirent->d_name[0] == '.')
            continue;

        char filepath[PATH_MAX + 1];
        snprintf(filepath, sizeof(filepath), "%s/%s", basedir, dirent->d_name);

        struct stat st;
        if (stat(filepath, &st) < 0) {
            if (errno != ENOENT)
                fprintf(stderr, "warn: stat(%s): %m\n", filepath);

            continue;
        }
        if (!S_ISDIR(st.st_mode))
            continue;

        uint16_t vendor, device;
        snprintf(filepath, sizeof(filepath), "%s/%s/vendor",
                 basedir, dirent->d_name);
        if (read_hex16(filepath, &vendor) < 0)
            continue;

        snprintf(filepath, sizeof(filepath), "%s/%s/device",
                 basedir, dirent->d_name);
        if (read_hex16(filepath, &device) < 0)
            continue;

        if (vendor == 0x1002 && (device == 0x515e || device == 0x5159)) {
            snprintf(devicepath, devicepathsize, "%s/%s", basedir,
                     dirent->d_name);
            return 0;
        }
    }
    closedir(dir);

    return -1;
}


int load_microcode(void)
{
    uint32_t *microcode = (uint32_t *)R100_cp;

    /* FIXME: Add support for more than R100? */

    printf("  Loading CP microcode\n");

    wait_for_idle(RBBM_STATUS_GUI_ACTIVE_MASK);

    write32(RADEON_CP_ME_RAM_ADDR, 0);
    size_t i;
    for (i = 0; i < sizeof(R100_cp) / sizeof(microcode[0]); i += 2) {
        write32(RADEON_CP_ME_RAM_DATAH, ntohl(microcode[i]));
        write32(RADEON_CP_ME_RAM_DATAL, ntohl(microcode[i + 1]));
    }

    return 0;
}


#define MEMMAP			"/sys/firmware/memmap"

#define L2_PAGETABLE_SHIFT	21

#define PAGETABLE_ORDER		9
#define L2_PAGETABLE_ENTRIES	(1 << PAGETABLE_ORDER)

/* First 16M is reserved for various purposes in Xen */
#define BOOTSTRAP_MAP_BASE	(16 * 1024 * 1024)

#define min(x,y) ({ \
	const typeof(x) _x = (x);	\
	const typeof(y) _y = (y);	\
	(void) (&_x == &_y);		\
	_x < _y ? _x : _y; })
#define min_t(type,x,y) \
	({ type __x = (x); type __y = (y); __x < __y ? __x: __y; })
#define max_t(type,x,y) \
	({ type __x = (x); type __y = (y); __x > __y ? __x: __y; })


int locate_hypervisor(uint32_t *paddr)
{
    /*
     * The Xen hypervisor code is relocated shortly after it starts. The
     * location is calculated via a somewhat complicated algorithm that
     * scans the E820 table and finds the first location that meets some
     * criteria and then relocates to the end of the address space (with
     * some alignment)
     *
     * Since the virtual address of the hypervisor code is fixed, it would
     * be ideal to walk the page tables to find where the hypervisor code
     * is relocated to, but I haven't been able to find a way to find the
     * page table (no access to the hypervisor CR3 register)
     *
     * While not ideal, this code replicates the logic in Xen which scans
     * the E820 tables to find a suitable location. Thankfully dom0 has
     * access to effectively the same E820 table the hypervisor uses.
     */

    int i;
    for (i = 256; i >= 0; i--) {
        char filepath[PATH_MAX + 1];

        snprintf(filepath, sizeof(filepath), MEMMAP "/%d", i);
        struct stat st;
        if (stat(filepath, &st) < 0) {
            if (errno == ENOENT)
                continue;

            fprintf(stderr, "error: stat(%s): %m\n", filepath);
            return -1;
        }

        /* Read type first */
        snprintf(filepath, sizeof(filepath), MEMMAP "/%d/type", i);
        FILE *f = fopen(filepath, "r");
        if (!f) {
            fprintf(stderr, "error: fopen(%s): %m\n", filepath);
            return -1;
        }

        char type[256];
        char *ret = fgets(type, sizeof(type), f);
        fclose(f);
        if (!ret) {
            fprintf(stderr, "error: fgets(%s): %m\n", filepath);
            return -1;
        }

        if (strcmp(type, "System RAM\n") != 0)
            /* Unusable memory range, skip it */
            continue;

        snprintf(filepath, sizeof(filepath), MEMMAP "/%d/start", i);
        uint64_t memstart;
        if (read_hex64(filepath, &memstart) < 0)
            return -1;

        snprintf(filepath, sizeof(filepath), MEMMAP "/%d/end", i);
        uint64_t memend;
        if (read_hex64(filepath, &memend) < 0)
            return -1;

        uint64_t memsize = memend - memstart + 1;

        /* Duplicated logic from Xen */

        /* Xen uses 2MB page table entries for the code, as a result, the
         * start and end has to be 2MB aligned */
        uint64_t mask = (1ULL << L2_PAGETABLE_SHIFT) - 1;

        /* Highest address that can be addressed by L2 page table. This
         * effectively creates an artificial limit to the highest physical
         * address the hypervisor can be relocated to. This turns out to be
         * 2^32 (4GB) */
        uint64_t limit = ((uint64_t)(4 * L2_PAGETABLE_ENTRIES) <<
                          L2_PAGETABLE_SHIFT);

        /* Align the start and end physical addresses */
        uint64_t s = (memstart + mask) & ~mask;
        uint64_t e = (memstart + memsize) & ~mask;

        /* Anything below the bootstrap base is reserved, so ensure this
         * code never tries to use that memory */
        s = max_t(uint64_t, s, BOOTSTRAP_MAP_BASE);

        if (s >= e)
            /* Adjusted start is after end. Region is too small, ignore */
            continue;

        uint64_t end = 0;
        if (s < limit)
            /* Don't try to place anything above the maximum address either */
            end = min(e, limit);

        /* Limit the end to be 44-bit address space */
        e = min_t(uint64_t, e, 1ULL << (PAGE_SHIFT + 32));

        /* FIXME: Xen then tries to make sure this doesn't overlap with
         * multiboot modules. We don't have that information, but it
         * appears that our systems don't use any multiboot modules */

        if (e > limit)
            /* Ignore any regions where the end is too high */
            end = 0;

        if (end > s) {
            /* FIXME: This assumes the size of the hypervisor code is
             * between 2MB and 4MB */
            e = end - (4 * 1024 * 1024);

            *paddr = e;
            return 0;
        }
    }

    fprintf(stderr, "error: unable to locate hypervisor code\n");

    return -1;
}


/* The cookie is used to make sure that install_patch is processing a valid
 * .raxlpxs file.
 */
int _check_cookie(int fd, const char *filename)
{
    char cookie[9];

    if (_read(fd, filename, cookie, sizeof(cookie) - 1) < 0)
        return -1;

    cookie[sizeof(cookie) - 1] = '\0';

    if (strncmp(cookie, XSPATCH_COOKIE, sizeof(cookie) - 1)) {
        fprintf(stderr, "error: cookie invalid: expected=%s actual=%s\n",
                XSPATCH_COOKIE, cookie);
        return -1;
    }

    return 0;
}


int configure_radeon(void)
{
    printf("\nSwitching device out of legacy VGA mode\n");

    /* Stop CP first */
    write32(RADEON_CP_CSQ_MODE, 0);
    write32(RADEON_CP_CSQ_CNTL, 0);
    write32(RADEON_SCRATCH_UMSK, 0);

    /*
     * Reset ASIC
     */
    uint32_t tmp = read32(RADEON_RBBM_STATUS);
    if (REG_SET(RBBM_STATUS_GUI_ACTIVE, tmp)) {
        printf("  Resetting ASIC\n");

        uint32_t tmp = read32(RADEON_CP_RB_CNTL);
        write32(RADEON_CP_RB_CNTL, tmp | RADEON_RB_RPTR_WR_ENA);
        write32(RADEON_CP_RB_RPTR_WR, 0);
        write32(RADEON_CP_RB_WPTR, 0);
        write32(RADEON_CP_RB_CNTL, tmp);

        /* Disable bus mastering */
        tmp = read32(RADEON_BUS_CNTL);
        tmp |= RADEON_BUS_MASTER_DIS;
        write32(RADEON_BUS_CNTL, tmp);

        /* Soft-reset other engines */
	write32(R_0000F0_RBBM_SOFT_RESET,
                S_0000F0_SOFT_RESET_SE(1) |
                S_0000F0_SOFT_RESET_RE(1) |
                S_0000F0_SOFT_RESET_PP(1) |
                S_0000F0_SOFT_RESET_RB(1));
	read32(R_0000F0_RBBM_SOFT_RESET);
	usleep(500 * 1000);
	write32(R_0000F0_RBBM_SOFT_RESET, 0);
	usleep(1000);
	tmp = read32(RADEON_RBBM_STATUS);
        printf("  RBBM_STATUS = %08lx\n", tmp);

        /* Soft-reset CP */
        write32(R_0000F0_RBBM_SOFT_RESET, S_0000F0_SOFT_RESET_CP(1));
        read32(R_0000F0_RBBM_SOFT_RESET);
        usleep(500 * 1000);
        write32(R_0000F0_RBBM_SOFT_RESET, 0);
        usleep(1000);
        tmp = read32(RADEON_RBBM_STATUS);
        printf("  RBBM_STATUS = %08lx\n", tmp);

        /* Check if GPU is idle */
        if (REG_SET(RBBM_STATUS_SE_BUSY, tmp) ||
            REG_SET(RBBM_STATUS_RE_BUSY, tmp) ||
            REG_SET(RBBM_STATUS_TAM_BUSY, tmp) ||
            REG_SET(RBBM_STATUS_PB_BUSY, tmp)) {
            printf("error: failed to reset ASIC\n");
            return -1;
        }
        printf("  ASIC reset successful\n");
    }

    /*
     * Disable CP
     */
    printf("  Setting up CP\n");

    if (load_microcode() < 0)
        return -1;

    /* Disable VGA */
    printf("  Disabling legacy VGA\n");

    tmp = read8(R_0003C2_GENMO_WT);
    write8(R_0003C2_GENMO_WT, C_0003C2_VGA_RAM_EN & tmp);

    /*
     * Start clock
     */
    printf("  Enabling clocks\n");

    write8(RADEON_CLOCK_CNTL_INDEX, R_00000D_SCLK_CNTL);
    tmp = read32(RADEON_CLOCK_CNTL_DATA);
    usleep(5000);	/* RV100 errata */

    tmp |= S_00000D_FORCE_CP(1) | S_00000D_FORCE_VIP(1);

    write8(RADEON_CLOCK_CNTL_INDEX, R_00000D_SCLK_CNTL | RADEON_PLL_WR_EN);
    write32(RADEON_CLOCK_CNTL_DATA, tmp);
    usleep(5000);	/* RV100 errata */

    /*
     * Setup MC
     */

    /* GTT needs to be at least 32MB. We only allocate one page for the
     * page for the page table (good for 4MB) and just won't reference
     * anything above that amount. */
    size_t ptsize = 4096;
    size_t gtt_size = 32 * 1024 * 1024;

    /* Place GTT before VRAM location */
    radeon.gtt_start = radeon.vramres.start - gtt_size;
    radeon.gtt_end = radeon.gtt_start + gtt_size - 1;
    printf("  GTT @ %08lx (%ZuMB)\n", radeon.gtt_start,
           gtt_size / (1024 * 1024));

    radeon.pt = align_malloc(ptsize);
    memset((void *)radeon.pt, 0, ptsize);

    /* Fill the entire page table to point to dummy page */
    radeon.dummy = align_malloc(4096);
    memset(radeon.dummy, 0, 4096);

    size_t i;
    for (i = 0; i < ptsize / sizeof(radeon.pt[0]); i++)
        radeon.pt[i] = get_physical_address(radeon.dummy);

    /* Enable bus mastering */
    tmp = read32(RADEON_BUS_CNTL);
    tmp &= ~RADEON_BUS_MASTER_DIS;
    write32(RADEON_BUS_CNTL, tmp);

    /*
     * Program PCI GART
     */

    printf("  Setting up PCI GART\n");

    /* Disable use of the PCI GART while we program it */
    tmp = read32(RADEON_AIC_CNTL) | RADEON_DIS_OUT_OF_PCI_GART_ACCESS;
    write32(RADEON_AIC_CNTL, tmp);

    /* Set range of address translation */
    write32(RADEON_AIC_LO_ADDR, radeon.gtt_start);
    write32(RADEON_AIC_HI_ADDR, radeon.gtt_end);

    write32(RADEON_AIC_PT_BASE, get_physical_address(radeon.pt));
    write32(RADEON_AIC_CNTL, tmp | RADEON_PCIGART_TRANSLATE_EN);

    write32(R_00014C_MC_AGP_LOCATION, 0x0FFFFFFF);
    write32(R_000170_AGP_BASE, 0);

    /*
     * Setup ring buffer
     */

    printf("  Setting up ring buffer\n");

    /* Not sure why this is necessary, but the GTT won't be used if this
     * isn't set */
    write32(RADEON_MC_FB_LOCATION,
            (radeon.vramres.start >> 16) |
             ((radeon.vramres.start + radeon.vram_size - 1) & 0xffff0000));

    /* Allocate enough memory to fit in one page */
    size_t ring_size = 4096;
    radeon.ring_entries = ring_size / sizeof(uint32_t);

    write32(RADEON_CP_RB_WPTR_DELAY, 0);

    int rb_bufsz = order_base_2(ring_size / 8);
    tmp = REG_SET(RADEON_RB_BUFSZ, rb_bufsz) |
          RADEON_RB_NO_UPDATE;

    write32(RADEON_CP_RB_CNTL, tmp);

    /* Place ring into VRAM */
    /* FIXME: Don't hardcode this location */
    radeon.ring = (volatile uint32_t *)(radeon.vram + (16 * 1024 * 1024));
    memset((void *)radeon.ring, 0, ring_size);
    write32(RADEON_CP_RB_BASE, radeon.vramres.start + (16 * 1024 * 1024));

    write32(RADEON_CP_RB_CNTL, tmp | RADEON_RB_RPTR_WR_ENA);
    write32(RADEON_CP_RB_RPTR_WR, 0);
    write32(RADEON_CP_RB_WPTR, radeon.wptr);
    write32(RADEON_CP_RB_CNTL, tmp);

    write32(RADEON_SCRATCH_UMSK, 0);

    wait_for_idle(RBBM_STATUS_CP_BUSY_MASK);

    /* Start ring */
    write32(RADEON_ISYNC_CNTL, RADEON_ISYNC_ANY2D_IDLE3D |
                               RADEON_ISYNC_ANY3D_IDLE2D |
                               RADEON_ISYNC_WAIT_IDLEGUI |
                               RADEON_ISYNC_CPSCRATCH_IDLEGUI);

    /* Enable bus mastering for primary stream and disable indirect streams */
    write32(RADEON_CP_CSQ_MODE, 0);
    write32(RADEON_CP_CSQ_CNTL, RADEON_CSQ_PRIBM_INDDIS);

    /*
     * Test ring. This writes a value to a scratch register, then adds
     * a packet to have the CP change the scratch register.
     */

    /* FIXME: This doesn't seem to always work. After the timeout, scratch
     * reg0 is set to 0 sometimes (rarely) */

    printf("  Testing ring: ");
    fflush(stdout);

    /* Write initial value to scratch register */
    write32(RADEON_SCRATCH_REG0, 0xCAFEDEAD);

    /* Insert Type-0 packet to write to scratch register */
    ADDRING(PACKET0(RADEON_SCRATCH_REG0, 0));
    ADDRING(0xDEADBEEF);

    /* Commit */
    wb();
    write32(RADEON_CP_RB_WPTR, radeon.wptr);
    read32(RADEON_CP_RB_WPTR);

    /* Read scratch register and see if it gets updated */
    if (wait_for_scratch_reg(0xDEADBEEF) < 0)
        return -1;

    printf("OK\n");

    return 0;
}


int release_radeon(void)
{
    /* Reset the FB location to the default value so the screen works
     * again */
    printf("\nSwitching device back to legacy VGA mode\n");
    write32(RADEON_MC_FB_LOCATION, 0xffff0000);

    /*
     * Disable CP
     */
    printf("  Disabling CP\n");
    wait_for_idle(RBBM_STATUS_CP_BUSY_MASK);
    write32(RADEON_CP_CSQ_MODE, 0);
    write32(RADEON_CP_CSQ_CNTL, 0);
    write32(RADEON_SCRATCH_UMSK, 0);
    wait_for_idle(RBBM_STATUS_GUI_ACTIVE_MASK);

    /*
     * Disable GART
     */
    printf("  Disabling PCI GART\n");
    uint32_t tmp = read32(RADEON_AIC_CNTL) | RADEON_DIS_OUT_OF_PCI_GART_ACCESS;
    tmp &= ~RADEON_PCIGART_TRANSLATE_EN;
    write32(RADEON_AIC_CNTL, tmp);
    write32(RADEON_AIC_LO_ADDR, 0);
    write32(RADEON_AIC_HI_ADDR, 0);
    write32(RADEON_AIC_PT_BASE, 0);
}


int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr, "error: need patch filename\n");
        return 1;
    }

    char *argv0 = argv[0];
    char *p = strrchr(argv0, '/');
    if (p)
        argv0 = p + 1;  /* Don't want to start at the / */

    printf("%s version 1.2 (built " __DATE__ " " __TIME__ ")\n\n", argv0);

    int result = 1;
    char *filename = argv[1];

    int fd = open(filename, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "error: open(%s): %m\n", filename);
        return 1;
    }

    if (_check_cookie(fd, filename) < 0)
        return 1;

    /* Read Xen version and compile date */
    char pxenversion[32];
    char pxencompiledate[32];
    if (_read(fd, filename, pxenversion, sizeof(pxenversion)) < 0)
        return 1;
    if (_read(fd, filename, pxencompiledate, sizeof(pxencompiledate)) < 0)
        return 1;

    /* Pull the crowbarabs out */
    uint64_t crowbarabs;
    if (_readu64(fd, filename, &crowbarabs) < 0)
        return 1;

    if (crowbarabs == 0) {
        fprintf(stderr, "error: expecting crowbar style patch\n");
        return 1;
    }

    /* Pull the blob out */
    uint64_t refabs;
    if (_readu64(fd, filename, &refabs) < 0)
        return 1;

    uint32_t bloblen;
    if (_readu32(fd, filename, &bloblen) < 0)
        return 1;

    unsigned char *blob = _zalloc(bloblen);
    if (_read(fd, filename, blob, bloblen) < 0)
        return 1;

    /* Second stage relocations should be empty */
    uint16_t numrelocs;
    if (_readu16(fd, filename, &numrelocs) < 0)
        return 1;

    if (numrelocs != 0) {
        fprintf(stderr, "error: cannot handle second stage relocations\n");
        return 1;
    }

    /* Pull out check data */
    uint16_t numchecks;
    if (_readu16(fd, filename, &numchecks) < 0)
        return 1;

    if (numchecks == 0) {
        fprintf(stderr, "error: expected at least one check\n");
        return 1;
    }

    struct check *checks = _zalloc(sizeof(struct check) * numchecks);
    size_t i;
    for (i = 0; i < numchecks; i++) {
        struct check *check = &checks[i];

        if (_readu64(fd, filename, &check->hvabs) < 0)
            return 1;
        if (_readu16(fd, filename, &check->datalen) < 0)
            return 1;

        check->data = _zalloc(check->datalen);
        if (_read(fd, filename, check->data, check->datalen) < 0)
            return 1;
    }

    /* Pull out number of function patches */
    uint16_t numfuncpatches;
    if (_readu16(fd, filename, &numfuncpatches) < 0)
        return 1;

    if (numfuncpatches != 0) {
        fprintf(stderr, "error: cannot handle function patches\n");
        return 1;
    }

    uint16_t numtablepatches;
    if (_readu16(fd, filename, &numtablepatches) < 0)
        return 1;

    if (numtablepatches == 0) {
        fprintf(stderr, "error: expected at least one table patch\n");
        return 1;
    }

    struct tablepatch *tablepatches = _zalloc(sizeof(struct tablepatch) *
                                              numtablepatches);
    for (i = 0; i < numtablepatches; i++) {
        struct tablepatch *tp = &tablepatches[i];

        uint16_t tablenamelen;
        if (_readu16(fd, filename, &tablenamelen) < 0)
            return 1;

        tp->tablename = _zalloc(tablenamelen + 1);
        if (_read(fd, filename, tp->tablename, tablenamelen) < 0)
            return 1;

        if (_readu64(fd, filename, &tp->hvabs) < 0)
            return 1;

        if (_readu16(fd, filename, &tp->datalen) < 0)
            return 1;

        tp->data = _zalloc(tp->datalen);
        if (_read(fd, filename, tp->data, tp->datalen) < 0)
            return 1;
    }

    close(fd);

    /* Make sure this patch applies to this version of Xen */
    char rxenversion[255];
    char rxencompiledate[255];

    if (get_xen_version(rxenversion, sizeof(rxenversion)) < 0)
        return 1;
    if (get_xen_compile_date(rxencompiledate, sizeof(rxencompiledate)) < 0)
        return 1;

    printf("Running Xen Information:\n");
    printf("  Hypervisor Version: %s\n", rxenversion);
    printf("  Hypervisor Compile Date: %s\n", rxencompiledate);

    printf("\n");
    printf("Patch Applies To:\n");
    printf("  Hypervisor Version: %s\n", pxenversion);
    printf("  Hypervisor Compile Date: %s\n", pxencompiledate);

    if (strcmp(rxenversion, pxenversion) != 0 ||
        strcmp(rxencompiledate, pxencompiledate) != 0) {
        fprintf(stderr, "error: patch does not match hypervisor build\n");
        return 1;
    }

    char devicepath[PATH_MAX + 1];
    if (find_device("/sys/bus/pci/devices", devicepath,
                    sizeof(devicepath)) < 0) {
        fprintf(stderr, "error: could not find suitable radeon device\n");
        return 1;
    }

    printf("\nFound Radeon device\n");
    printf("  sysfs file: %s\n", devicepath);

    memset(&radeon, 0, sizeof(radeon));
    radeon.mmiores.num = -1;
    radeon.vramres.num = -1;

    /* Load resource map */
    char resourcepath[PATH_MAX + 1];
    snprintf(resourcepath, sizeof(resourcepath), "%s/resource", devicepath);
    FILE *f = fopen(resourcepath, "r");
    if (!f) {
        fprintf(stderr, "error: open(%s): %m\n", resourcepath);
        return 1;
    }

    for (i = 0; !feof(f); i++) {
        uint64_t start, end, flags;
        if (fscanf(f, "0x%llx 0x%llx 0x%llx\n", &start, &end, &flags) != 3)
            continue;

        if (!flags)
            /* Resource doesn't exist */
            continue;

        uint64_t size = (end - start) + 1;
        unsigned int type = flags & IORESOURCE_TYPE_BITS;

        if (type != IORESOURCE_MEM)
            /* Both MMIO and VRAM show up as memory resources */
            continue;

        if (flags & IORESOURCE_READONLY)
            /* ROM, ignore */
            continue;

        /* Could either be VRAM or MMIO, differentiate based on size */
        struct resource *resource;
        if (size < 1024 * 1024) {
            resource = &radeon.mmiores;
            printf("  MMIO ");
        } else {
            resource = &radeon.vramres;
            printf("  VRAM ");
        }

        if (resource->num != -1) {
            fprintf(stderr, "error: duplicate resource found\n");
            return 1;
        }

        resource->num = i;
        resource->start = start;
        resource->size = size;

        printf("@ %08lx", start);
        if (size < 1024 * 1024)
            printf(" (%uKB)\n", size / 1024);
        else
            printf(" (%uMB)\n", size / (1024 * 1024));
    }
    fclose(f);

    if (radeon.mmiores.num == -1) {
        fprintf(stderr, "error: could not find MMIO for device\n");
        return 1;
    }
    if (radeon.vramres.num == -1) {
        fprintf(stderr, "error: could not find VRAM for device\n");
        return 1;
    }

    /* Map MMIO */
    snprintf(resourcepath, sizeof(resourcepath), "%s/resource%d",
             devicepath, radeon.mmiores.num);
    int mmiofd = open(resourcepath, O_RDWR);
    if (mmiofd < 0) {
        fprintf(stderr, "error: open(%s): %m\n", resourcepath);
        return 1;
    }

    struct stat st;
    if (stat(resourcepath, &st) < 0) {
        fprintf(stderr, "error: stat(%s): %m\n", resourcepath);
        return 1;
    }

    size_t mmio_mmap_size = st.st_size;
    radeon.mmio = mmap(0, mmio_mmap_size, PROT_READ | PROT_WRITE, MAP_SHARED,
                       mmiofd, 0);
    if (radeon.mmio == MAP_FAILED) {
        fprintf(stderr, "error: mmap(%s): %m\n", resourcepath);
        return 1;
    }

    radeon.vram_size = read32(RADEON_CONFIG_MEMSIZE);
    printf("  Actual VRAM size: %dMB\n", radeon.vram_size / (1024 * 1024));

    /* Map VRAM */
    /* VRAM is always resource 0 */
    snprintf(resourcepath, sizeof(resourcepath), "%s/resource%d",
             devicepath, radeon.vramres.num);
    int vramfd = open(resourcepath, O_RDWR);
    if (vramfd < 0) {
        fprintf(stderr, "open(%s): %m\n", resourcepath);
        return 1;
    }

    if (stat(resourcepath, &st) < 0) {
        fprintf(stderr, "error: stat(%s): %m\n", resourcepath);
        return 1;
    }

    size_t vram_mmap_size = st.st_size;
    radeon.vram = mmap(0, vram_mmap_size, PROT_READ | PROT_WRITE, MAP_SHARED,
                       vramfd, 0);
    if (radeon.vram == MAP_FAILED) {
        fprintf(stderr, "mmap(%s): %m\n", resourcepath);
        return 1;
    }

    /* FIXME: The ring buffer test fails sometimes. I haven't been able to
     * figure out why, but retrying usually works fine */
    i = 0;
    while (1) {
        if (configure_radeon() == 0)
            /* Success */
            break;

        i++;

        if (i >= 5) {
            printf("error: too many tries, giving up\n");
            goto out;
        }

        printf("warn: radeon configure failed, retrying\n");

        release_radeon();
    }

    /* Figure out where the hypervisor code is in physical memory */
    uint32_t codepaddr;

    if (locate_hypervisor(&codepaddr) < 0)
        goto out;

    /*
     * Verify everything matches what we expect before changing anything
     */
    uint64_t virt_start = crowbarabs & ~0xFFFFFF;

    printf("\nPerforming prechecks:\n");
    fflush(stdout);

    /* Check the table writes first. If these match, then it's already
     * patched */
    int matches = 0;
    for (i = 0; i < numtablepatches; i++) {
        struct tablepatch *tp = &tablepatches[i];

        uint32_t paddr = tp->hvabs - virt_start + codepaddr;
        unsigned char *buf = copy_from(paddr, 4096, 0);
        if (!buf)
            goto out;

        if (memcmp(buf, tp->data, tp->datalen) == 0)
            matches++;
    }

    if (matches == numtablepatches) {
        printf("  Already patched, skipping\n");
        goto success;
    }

    for (i = 0; i < numchecks; i++) {
        struct check *check = &checks[i];

        printf("  %u bytes @ %llx\n", check->datalen, check->hvabs);

        uint32_t paddr = check->hvabs - virt_start + codepaddr;

        /* FIXME: This should probably be check->datalen instead of 4096 */
        unsigned char *buf = copy_from(paddr, 4096, 0);
        if (!buf)
            goto out;

        if (memcmp(buf, check->data, check->datalen) != 0) {
            fprintf(stderr, "error: check failed\n");
            goto out;
        }
    }

    /* All of our sanity checks passed, time to start writing */

    /* Write new blob */
    printf("\nWriting patches:\n");

    printf("  blob @ %llx\n", crowbarabs);
    uint32_t paddr = crowbarabs - virt_start + codepaddr;
    unsigned char *buf = copy_from(paddr, bloblen, 0);
    if (!buf)
        goto out;

    memcpy(buf, blob, bloblen);

    if (copy_to(0, bloblen, paddr) < 0)
        goto out;

    /* Update tables */
    for (i = 0; i < numtablepatches; i++) {
        struct tablepatch *tp = &tablepatches[i];

        printf("  table %s @ %llx\n", tp->tablename, tp->hvabs);

        uint32_t paddr = tp->hvabs - virt_start + codepaddr;
        unsigned char *buf = copy_from(paddr, 4096, 0);
        if (!buf)
            goto out;

        memcpy(buf, tp->data, tp->datalen);

        if (copy_to(0, 4096, paddr) < 0)
            goto out;
    }

success:
    result = 0;

out:
    release_radeon();

    /* Free memory and resources */
    munmap((void *)radeon.vram, vram_mmap_size);
    close(vramfd);

    munmap((void *)radeon.mmio, mmio_mmap_size);
    close(mmiofd);

    return result;
}
