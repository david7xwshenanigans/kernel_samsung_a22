/*
 * RAMLOG Early Console - Debugging tool for "Silent Death" kernels
 *
 * LK reserves a persistent DRAM window at 0x4d010000..0x4d0effff.
 * Ramoops occupies the front 0x40000 bytes, and ramlog uses the tail that
 * starts at 0x4d060000. Early boot is limited by arm64 early_ioremap() to a
 * single 256 KiB fixmap window, so we start with that size and upgrade to the
 * full ramlog-owned tail once normal vmalloc/vmap mappings are available.
 */

#include <linux/console.h>
#include <linux/init.h>
#include <linux/io.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/vmalloc.h>
#include <linux/serial_core.h>
#include <asm/early_ioremap.h>

#define RAMLOG_RESERVED_PADDR	0x4d010000UL
#define RAMLOG_RESERVED_SIZE	0x000e0000UL
#define RAMLOG_PADDR		0x4d060000UL
#define RAMLOG_EARLY_SIZE	0x00040000UL
#define RAMLOG_END_HEADROOM	0x00010000UL
#define RAMLOG_RESERVED_END	(RAMLOG_RESERVED_PADDR + RAMLOG_RESERVED_SIZE)
#define RAMLOG_USABLE_END	(RAMLOG_RESERVED_END - RAMLOG_END_HEADROOM)
#define RAMLOG_LATE_SIZE	(RAMLOG_USABLE_END - RAMLOG_PADDR)

static void __iomem *ramlog_base;
static unsigned long ramlog_idx;
static unsigned long ramlog_size = RAMLOG_EARLY_SIZE;
static DEFINE_RAW_SPINLOCK(ramlog_lock);

static void __iomem *ramlog_remap_reserved_nocache(phys_addr_t start,
						   phys_addr_t size)
{
	struct page **pages;
	phys_addr_t page_start;
	unsigned int page_count;
	unsigned int i;
	pgprot_t prot;
	void *vaddr;

	page_start = start - offset_in_page(start);
	page_count = DIV_ROUND_UP(size + offset_in_page(start), PAGE_SIZE);
	prot = pgprot_noncached(PAGE_KERNEL);

	pages = kmalloc_array(page_count, sizeof(*pages), GFP_KERNEL);
	if (!pages)
		return NULL;

	for (i = 0; i < page_count; i++)
		pages[i] = pfn_to_page((page_start >> PAGE_SHIFT) + i);

	vaddr = vmap(pages, page_count, VM_MAP, prot);
	kfree(pages);
	if (!vaddr)
		return NULL;

	return (void __iomem *)(vaddr + offset_in_page(start));
}

/*
 * The writing function.
 * Called by printk() -> early_console->write()
 */
static void ramlog_write(struct console *con, const char *s, unsigned int n)
{
	unsigned long flags;
	unsigned long size;
	unsigned int i;
	void __iomem *base;

	raw_spin_lock_irqsave(&ramlog_lock, flags);
	base = ramlog_base;
	size = ramlog_size;
	if (!base || size <= 4) {
		raw_spin_unlock_irqrestore(&ramlog_lock, flags);
		return;
	}

	for (i = 0; i < n; i++) {
		/* Calculate circular buffer offset */
		/* We start at offset 4 to preserve the signature */
		unsigned long offset = 4 + (ramlog_idx % (size - 4));

		writeb(s[i], base + offset);
		ramlog_idx++;
	}

	/*
	 * Write Memory Barrier:
	 * Ensures the CPU flushes the write buffer to DRAM immediately.
	 * Critical for catching crashes that happen microseconds later.
	 */
	wmb();
	raw_spin_unlock_irqrestore(&ramlog_lock, flags);
}

/*
 * Initialization.
 * Called when kernel parses "earlycon=ramlog"
 */
static int __init ramlog_early_setup(struct earlycon_device *device,
				     const char *options)
{
	BUILD_BUG_ON(RAMLOG_PADDR < RAMLOG_RESERVED_PADDR);
	BUILD_BUG_ON(RAMLOG_RESERVED_END <= RAMLOG_PADDR);
	BUILD_BUG_ON(RAMLOG_USABLE_END <= RAMLOG_PADDR);
	BUILD_BUG_ON(RAMLOG_EARLY_SIZE > RAMLOG_LATE_SIZE);

	/* Map the physical memory.
	 * early_ioremap works inside setup_arch(), very early.
	 */
	ramlog_base = early_ioremap(RAMLOG_PADDR, RAMLOG_EARLY_SIZE);

	if (!ramlog_base)
		return -ENOMEM;

	/* Start each boot with a clean capture buffer. */
	memset_io(ramlog_base, 0, RAMLOG_EARLY_SIZE);
	ramlog_idx = 0;
	ramlog_size = RAMLOG_EARLY_SIZE;

	/*
	 * Write Signature "BOOT" (0x544F4F42) at the very start.
	 * This helps us find the buffer in a hex dump later.
	 */
	writel(0x544F4F42, ramlog_base);

	/* Hook our write function into the system console */
	device->con->write = ramlog_write;

	return 0;
}

static int __init ramlog_late_remap(void)
{
	size_t extra_size;
	void __iomem *old_base;
	void __iomem *new_base;
	unsigned long flags;

	if (!ramlog_base || RAMLOG_LATE_SIZE <= RAMLOG_EARLY_SIZE)
		return 0;

	extra_size = RAMLOG_LATE_SIZE - RAMLOG_EARLY_SIZE;
	if (!extra_size)
		return 0;

	new_base = ramlog_remap_reserved_nocache(RAMLOG_PADDR, RAMLOG_LATE_SIZE);
	if (!new_base) {
		pr_warn("ramlog: late remap failed for 0x%lx@0x%lx\n",
			RAMLOG_LATE_SIZE, (unsigned long)RAMLOG_PADDR);
		return 0;
	}

	/*
	 * Preserve the early capture, but clear the newly claimed extension
	 * before exposing it to the writer. Leave explicit headroom untouched
	 * at the far end of the LK-reserved window.
	 */
	memset_io((void __iomem *)((char __iomem *)new_base + RAMLOG_EARLY_SIZE),
		  0, extra_size);
	wmb();

	raw_spin_lock_irqsave(&ramlog_lock, flags);
	old_base = ramlog_base;
	ramlog_base = new_base;
	ramlog_size = RAMLOG_LATE_SIZE;
	raw_spin_unlock_irqrestore(&ramlog_lock, flags);

	early_iounmap(old_base, RAMLOG_EARLY_SIZE);
	pr_info("ramlog: upgraded mapping to 0x%lx bytes at 0x%lx, headroom 0x%lx\n",
		RAMLOG_LATE_SIZE, (unsigned long)RAMLOG_PADDR,
		(unsigned long)RAMLOG_END_HEADROOM);

	return 0;
}

/* Register the driver so "earlycon=ramlog" works */
EARLYCON_DECLARE(ramlog, ramlog_early_setup);
postcore_initcall(ramlog_late_remap);
