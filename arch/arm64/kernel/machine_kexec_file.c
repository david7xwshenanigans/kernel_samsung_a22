/* SPDX-License-Identifier: GPL-2.0 */
/*
 * kexec_file for arm64
 *
 * Copyright (C) 2018 Linaro Limited
 */

#define pr_fmt(fmt) "kexec_file: " fmt

#include <linux/cpu.h>
#include <linux/elf.h>
#include <linux/err.h>
#include <linux/ioport.h>
#include <linux/kernel.h>
#include <linux/kexec.h>
#include <linux/libfdt.h>
#include <linux/memblock.h>
#include <linux/of.h>
#include <linux/of_fdt.h>
#include <linux/percpu.h>
#include <linux/random.h>
#include <linux/sizes.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/vmalloc.h>

#include <asm/memory.h>
#include <asm/sections.h>

static struct kexec_file_ops *kexec_file_loaders[] = {
	&kexec_image_ops,
};

struct crash_mem_range {
	u64 start;
	u64 end;
};

struct crash_mem {
	unsigned int max_nr_ranges;
	unsigned int nr_ranges;
	struct crash_mem_range ranges[];
};

int arch_kexec_kernel_image_probe(struct kimage *image, void *buf,
				  unsigned long buf_len)
{
	int i, ret = -ENOEXEC;
	struct kexec_file_ops *fops;

	for (i = 0; i < ARRAY_SIZE(kexec_file_loaders); i++) {
		fops = kexec_file_loaders[i];
		if (!fops || !fops->probe)
			continue;

		ret = fops->probe(buf, buf_len);
		if (!ret) {
			image->fops = fops;
			return ret;
		}
	}

	return ret;
}

void *arch_kexec_kernel_image_load(struct kimage *image)
{
	if (!image->fops || !image->fops->load)
		return ERR_PTR(-ENOEXEC);

	return image->fops->load(image, image->kernel_buf,
				 image->kernel_buf_len, image->initrd_buf,
				 image->initrd_buf_len, image->cmdline_buf,
				 image->cmdline_buf_len);
}

int arch_kimage_file_post_load_cleanup(struct kimage *image)
{
	kvfree(image->arch.dtb);
	image->arch.dtb = NULL;
	image->arch.dtb_mem = 0;

	vfree(image->arch.elf_headers);
	image->arch.elf_headers = NULL;
	image->arch.elf_headers_sz = 0;
	image->arch.elf_load_addr = 0;

	if (!image->fops || !image->fops->cleanup)
		return 0;

	return image->fops->cleanup(image->image_loader_data);
}

#ifdef CONFIG_KEXEC_VERIFY_SIG
int arch_kexec_kernel_verify_sig(struct kimage *image, void *buf,
				 unsigned long buf_len)
{
	if (!image->fops || !image->fops->verify_sig)
		return -EKEYREJECTED;

	return image->fops->verify_sig(buf, buf_len);
}
#endif

static int fdt_find_and_del_mem_rsv(void *fdt, unsigned long start,
				    unsigned long size)
{
	int i, ret, num_rsvs = fdt_num_mem_rsv(fdt);

	for (i = 0; i < num_rsvs; i++) {
		u64 rsv_start, rsv_size;

		ret = fdt_get_mem_rsv(fdt, i, &rsv_start, &rsv_size);
		if (ret)
			return -EINVAL;

		if (rsv_start == start && rsv_size == size) {
			ret = fdt_del_mem_rsv(fdt, i);
			return ret ? -EINVAL : 0;
		}
	}

	return -ENOENT;
}

static int get_addr_size_cells(int *addr_cells, int *size_cells)
{
	struct device_node *root;

	root = of_find_node_by_path("/");
	if (!root)
		return -EINVAL;

	*addr_cells = of_n_addr_cells(root);
	*size_cells = of_n_size_cells(root);
	of_node_put(root);

	return 0;
}

static int write_cells(__be32 *prop, u64 val, int cells)
{
	switch (cells) {
	case 1:
		if (val > U32_MAX)
			return -EINVAL;
		prop[0] = cpu_to_fdt32((u32)val);
		return sizeof(*prop);
	case 2:
		prop[0] = cpu_to_fdt32((u32)(val >> 32));
		prop[1] = cpu_to_fdt32((u32)val);
		return sizeof(*prop) * 2;
	default:
		return -EINVAL;
	}
}

static int fdt_appendprop_addrrange(void *fdt, int nodeoffset,
				    const char *name, u64 addr, u64 size)
{
	__be32 value[4];
	int addr_cells, size_cells;
	int ret, len = 0;

	ret = get_addr_size_cells(&addr_cells, &size_cells);
	if (ret)
		return ret;

	ret = write_cells(value, addr, addr_cells);
	if (ret < 0)
		return ret;
	len += ret;

	ret = write_cells((__be32 *)((char *)value + len), size, size_cells);
	if (ret < 0)
		return ret;
	len += ret;

	return fdt_appendprop(fdt, nodeoffset, name, value, len);
}

static void *kexec_file_setup_fdt(const struct kimage *image,
				  unsigned long initrd_load_addr,
				  unsigned long initrd_len,
				  const char *cmdline)
{
	void *fdt;
	int ret, chosen_node, root, len;
	const void *prop;
	size_t fdt_size;

	fdt_size = fdt_totalsize(initial_boot_params) +
		   (cmdline ? strlen(cmdline) + 1 : 0) + 0x1000;
	fdt = kvmalloc(fdt_size, GFP_KERNEL);
	if (!fdt)
		return NULL;

	ret = fdt_open_into(initial_boot_params, fdt, fdt_size);
	if (ret)
		goto out;

	ret = fdt_find_and_del_mem_rsv(fdt, __pa(initial_boot_params),
				       fdt_totalsize(initial_boot_params));
	if (ret == -EINVAL)
		goto out;

	root = fdt_path_offset(fdt, "/");
	if (root < 0) {
		ret = root;
		goto out;
	}

	chosen_node = fdt_path_offset(fdt, "/chosen");
	if (chosen_node == -FDT_ERR_NOTFOUND)
		chosen_node = fdt_add_subnode(fdt, root, "chosen");
	if (chosen_node < 0) {
		ret = chosen_node;
		goto out;
	}

	ret = fdt_delprop(fdt, chosen_node, "linux,elfcorehdr");
	if (ret && ret != -FDT_ERR_NOTFOUND)
		goto out;

	ret = fdt_delprop(fdt, chosen_node, "linux,usable-memory-range");
	if (ret && ret != -FDT_ERR_NOTFOUND)
		goto out;

	prop = fdt_getprop(fdt, chosen_node, "linux,initrd-start", &len);
	if (prop) {
		u64 tmp_start, tmp_end, tmp_size;

		tmp_start = of_read_number(prop, len / 4);
		prop = fdt_getprop(fdt, chosen_node, "linux,initrd-end", &len);
		if (!prop) {
			ret = -EINVAL;
			goto out;
		}

		tmp_end = of_read_number(prop, len / 4);
		tmp_size = tmp_end - tmp_start;
		ret = fdt_find_and_del_mem_rsv(fdt, tmp_start, tmp_size);
		if (ret == -ENOENT)
			ret = fdt_find_and_del_mem_rsv(fdt, tmp_start,
						       round_up(tmp_size,
								PAGE_SIZE));
		if (ret == -EINVAL)
			goto out;
	}

	if (initrd_load_addr) {
		ret = fdt_setprop_u64(fdt, chosen_node, "linux,initrd-start",
				      initrd_load_addr);
		if (ret)
			goto out;

		ret = fdt_setprop_u64(fdt, chosen_node, "linux,initrd-end",
				      initrd_load_addr + initrd_len);
		if (ret)
			goto out;

		ret = fdt_add_mem_rsv(fdt, initrd_load_addr, initrd_len);
		if (ret)
			goto out;
	} else {
		ret = fdt_delprop(fdt, chosen_node, "linux,initrd-start");
		if (ret && ret != -FDT_ERR_NOTFOUND)
			goto out;

		ret = fdt_delprop(fdt, chosen_node, "linux,initrd-end");
		if (ret && ret != -FDT_ERR_NOTFOUND)
			goto out;
	}

	if (image->type == KEXEC_TYPE_CRASH) {
		ret = fdt_appendprop_addrrange(fdt, chosen_node,
					       "linux,elfcorehdr",
					       image->arch.elf_load_addr,
					       image->arch.elf_headers_sz);
		if (ret)
			goto out;

		ret = fdt_add_mem_rsv(fdt, image->arch.elf_load_addr,
				      image->arch.elf_headers_sz);
		if (ret)
			goto out;

		ret = fdt_appendprop_addrrange(fdt, chosen_node,
					       "linux,usable-memory-range",
					       crashk_res.start,
					       resource_size(&crashk_res));
		if (ret)
			goto out;

		if (crashk_low_res.end) {
			ret = fdt_appendprop_addrrange(fdt, chosen_node,
					       "linux,usable-memory-range",
					       crashk_low_res.start,
					       resource_size(&crashk_low_res));
			if (ret)
				goto out;
		}
	}

	if (cmdline) {
		ret = fdt_setprop_string(fdt, chosen_node, "bootargs", cmdline);
		if (ret)
			goto out;
	} else {
		ret = fdt_delprop(fdt, chosen_node, "bootargs");
		if (ret && ret != -FDT_ERR_NOTFOUND)
			goto out;
	}

	ret = fdt_delprop(fdt, chosen_node, "kaslr-seed");
	if (ret && ret != -FDT_ERR_NOTFOUND)
		goto out;

	if (rng_is_initialized()) {
		u64 seed = get_random_u64();

		ret = fdt_setprop_u64(fdt, chosen_node, "kaslr-seed", seed);
		if (ret)
			goto out;
	}

	ret = fdt_setprop(fdt, chosen_node, "linux,booted-from-kexec",
			  NULL, 0);
	if (ret)
		goto out;

	return fdt;

out:
	kvfree(fdt);
	return NULL;
}

static int crash_exclude_mem_range(struct crash_mem *mem,
				   unsigned long long mstart,
				   unsigned long long mend)
{
	int i, j;
	unsigned long long start, end, p_start, p_end;
	struct crash_mem_range temp_range = { 0, 0 };

	for (i = 0; i < mem->nr_ranges; i++) {
		start = mem->ranges[i].start;
		end = mem->ranges[i].end;
		p_start = mstart;
		p_end = mend;

		if (mstart > end || mend < start)
			continue;

		if (mstart < start)
			p_start = start;
		if (mend > end)
			p_end = end;

		if (p_start == start && p_end == end) {
			mem->ranges[i].start = 0;
			mem->ranges[i].end = 0;
			if (i < mem->nr_ranges - 1) {
				for (j = i; j < mem->nr_ranges - 1; j++)
					mem->ranges[j] = mem->ranges[j + 1];
				i--;
				mem->nr_ranges--;
				continue;
			}
			mem->nr_ranges--;
			return 0;
		}

		if (p_start > start && p_end < end) {
			mem->ranges[i].end = p_start - 1;
			temp_range.start = p_end + 1;
			temp_range.end = end;
		} else if (p_start != start) {
			mem->ranges[i].end = p_start - 1;
		} else {
			mem->ranges[i].start = p_end + 1;
		}
		break;
	}

	if (!temp_range.end)
		return 0;

	if (i == mem->max_nr_ranges - 1)
		return -ENOMEM;

	j = i + 1;
	if (j < mem->nr_ranges) {
		for (i = mem->nr_ranges - 1; i >= j; i--)
			mem->ranges[i + 1] = mem->ranges[i];
	}

	mem->ranges[j] = temp_range;
	mem->nr_ranges++;
	return 0;
}

static int crash_prepare_elf64_headers(struct crash_mem *mem, bool kernel_map,
				       void **addr, unsigned long *sz)
{
	Elf64_Ehdr *ehdr;
	Elf64_Phdr *phdr;
	unsigned long nr_cpus = num_possible_cpus();
	unsigned long nr_phdr, elf_sz;
	unsigned char *buf;
	unsigned int cpu, i;
	unsigned long long notes_addr;
	unsigned long mstart, mend;

	nr_phdr = nr_cpus + 1;
	nr_phdr += mem->nr_ranges;
	nr_phdr++;
	elf_sz = sizeof(Elf64_Ehdr) + nr_phdr * sizeof(Elf64_Phdr);
	elf_sz = ALIGN(elf_sz, PAGE_SIZE);

	buf = vzalloc(elf_sz);
	if (!buf)
		return -ENOMEM;

	ehdr = (Elf64_Ehdr *)buf;
	phdr = (Elf64_Phdr *)(ehdr + 1);
	memcpy(ehdr->e_ident, ELFMAG, SELFMAG);
	ehdr->e_ident[EI_CLASS] = ELFCLASS64;
	ehdr->e_ident[EI_DATA] = ELFDATA2LSB;
	ehdr->e_ident[EI_VERSION] = EV_CURRENT;
	ehdr->e_ident[EI_OSABI] = ELF_OSABI;
	memset(ehdr->e_ident + EI_PAD, 0, EI_NIDENT - EI_PAD);
	ehdr->e_type = ET_CORE;
	ehdr->e_machine = ELF_ARCH;
	ehdr->e_version = EV_CURRENT;
	ehdr->e_phoff = sizeof(Elf64_Ehdr);
	ehdr->e_ehsize = sizeof(Elf64_Ehdr);
	ehdr->e_phentsize = sizeof(Elf64_Phdr);

	for_each_present_cpu(cpu) {
		phdr->p_type = PT_NOTE;
		notes_addr = per_cpu_ptr_to_phys(per_cpu_ptr(crash_notes, cpu));
		phdr->p_offset = phdr->p_paddr = notes_addr;
		phdr->p_filesz = phdr->p_memsz = sizeof(note_buf_t);
		ehdr->e_phnum++;
		phdr++;
	}

	phdr->p_type = PT_NOTE;
	phdr->p_offset = phdr->p_paddr = paddr_vmcoreinfo_note();
	phdr->p_filesz = phdr->p_memsz = VMCOREINFO_NOTE_SIZE;
	ehdr->e_phnum++;
	phdr++;

	if (kernel_map) {
		phdr->p_type = PT_LOAD;
		phdr->p_flags = PF_R | PF_W | PF_X;
		phdr->p_vaddr = (unsigned long)_text;
		phdr->p_filesz = phdr->p_memsz = _end - _text;
		phdr->p_offset = phdr->p_paddr = __pa_symbol(_text);
		ehdr->e_phnum++;
		phdr++;
	}

	for (i = 0; i < mem->nr_ranges; i++) {
		mstart = mem->ranges[i].start;
		mend = mem->ranges[i].end;

		phdr->p_type = PT_LOAD;
		phdr->p_flags = PF_R | PF_W | PF_X;
		phdr->p_offset = mstart;
		phdr->p_paddr = mstart;
		phdr->p_vaddr = (unsigned long)__va(mstart);
		phdr->p_filesz = phdr->p_memsz = mend - mstart + 1;
		phdr->p_align = 0;
		ehdr->e_phnum++;
		phdr++;
	}

	*addr = buf;
	*sz = elf_sz;
	return 0;
}

static int prepare_elf_headers(void **addr, unsigned long *sz)
{
	struct crash_mem *cmem;
	struct memblock_region *reg;
	unsigned int nr_ranges;
	int ret;

	nr_ranges = 1;
	for_each_memblock(memory, reg)
		nr_ranges++;

	cmem = kmalloc(sizeof(*cmem) +
		       nr_ranges * sizeof(struct crash_mem_range),
		       GFP_KERNEL);
	if (!cmem)
		return -ENOMEM;

	cmem->max_nr_ranges = nr_ranges;
	cmem->nr_ranges = 0;
	for_each_memblock(memory, reg) {
		cmem->ranges[cmem->nr_ranges].start = reg->base;
		cmem->ranges[cmem->nr_ranges].end = reg->base + reg->size - 1;
		cmem->nr_ranges++;
	}

	ret = crash_exclude_mem_range(cmem, crashk_res.start, crashk_res.end);
	if (!ret)
		ret = crash_prepare_elf64_headers(cmem, true, addr, sz);

	kfree(cmem);
	return ret;
}

int load_other_segments(struct kimage *image,
			unsigned long kernel_load_addr,
			unsigned long kernel_size,
			char *initrd, unsigned long initrd_len,
			char *cmdline)
{
	struct kexec_buf kbuf;
	void *headers, *dtb = NULL;
	unsigned long headers_sz, initrd_load_addr = 0, dtb_len;
	unsigned long orig_segments = image->nr_segments;
	int ret = 0;

	memset(&kbuf, 0, sizeof(kbuf));
	kbuf.image = image;
	kbuf.buf_min = kernel_load_addr + kernel_size;

	if (image->type == KEXEC_TYPE_CRASH) {
		ret = prepare_elf_headers(&headers, &headers_sz);
		if (ret) {
			pr_err("Preparing elf core header failed\n");
			goto out_err;
		}

		kbuf.buffer = headers;
		kbuf.bufsz = headers_sz;
		kbuf.memsz = headers_sz;
		kbuf.buf_align = SZ_64K;
		kbuf.buf_max = ULONG_MAX;
		kbuf.top_down = true;

		ret = kexec_add_buffer(&kbuf);
		if (ret) {
			vfree(headers);
			goto out_err;
		}

		image->arch.elf_headers = headers;
		image->arch.elf_load_addr = kbuf.mem;
		image->arch.elf_headers_sz = headers_sz;
	}

	if (initrd) {
		kbuf.buffer = initrd;
		kbuf.bufsz = initrd_len;
		kbuf.memsz = initrd_len;
		kbuf.buf_align = 0;
		kbuf.buf_max = round_down(kernel_load_addr, SZ_1G) +
			       (unsigned long)SZ_1G * 32;
		kbuf.top_down = false;

		ret = kexec_add_buffer(&kbuf);
		if (ret)
			goto out_err;
		initrd_load_addr = kbuf.mem;
	}

	dtb = kexec_file_setup_fdt(image, initrd_load_addr, initrd_len,
				   cmdline);
	if (!dtb) {
		pr_err("Preparing for new dtb failed\n");
		ret = -EINVAL;
		goto out_err;
	}

	fdt_pack(dtb);
	dtb_len = fdt_totalsize(dtb);
	kbuf.buffer = dtb;
	kbuf.bufsz = dtb_len;
	kbuf.memsz = dtb_len;
	kbuf.buf_align = SZ_2M;
	kbuf.buf_max = ULONG_MAX;
	kbuf.top_down = true;

	ret = kexec_add_buffer(&kbuf);
	if (ret)
		goto out_err;

	image->arch.dtb = dtb;
	image->arch.dtb_mem = kbuf.mem;

	return 0;

out_err:
	image->nr_segments = orig_segments;
	kvfree(dtb);
	return ret;
}
