/*
 * DMABUF System heap exporter
 *
 * Copyright (C) 2011 Google, Inc.
 * Copyright (C) 2019, 2020 Linaro Ltd.
 * Portions based off of Andrew Davis' SRAM heap:
 * Copyright (C) 2019 Texas Instruments Incorporated
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published by
 * the Free Software Foundation.
 */

#include <linux/dma-buf.h>
#include <linux/dma-heap.h>
#include <linux/dma-mapping.h>
#include <linux/err.h>
#include <linux/highmem.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/sched/signal.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>

static struct dma_heap *sys_heap;

struct system_heap_buffer {
	struct dma_heap *heap;
	struct list_head attachments;
	struct mutex lock;
	unsigned long len;
	struct sg_table sg_table;
	int vmap_cnt;
	void *vaddr;
};

struct dma_heap_attachment {
	struct device *dev;
	struct sg_table *table;
	struct list_head list;
	bool mapped;
};

#define HIGH_ORDER_GFP (((GFP_HIGHUSER | __GFP_ZERO | __GFP_NOWARN | \
			  __GFP_NORETRY) & ~__GFP_RECLAIM) | __GFP_COMP)
#define LOW_ORDER_GFP (GFP_HIGHUSER | __GFP_ZERO | __GFP_COMP)

static gfp_t order_flags[] = { HIGH_ORDER_GFP, LOW_ORDER_GFP, LOW_ORDER_GFP };
static const unsigned int orders[] = { 8, 4, 0 };

static int dma_heap_map_sgtable(struct device *dev, struct sg_table *table,
				enum dma_data_direction direction)
{
	int nents;

	nents = dma_map_sg(dev, table->sgl, table->orig_nents, direction);
	if (!nents)
		return -ENOMEM;

	table->nents = nents;
	return 0;
}

static void dma_heap_unmap_sgtable(struct device *dev, struct sg_table *table,
				   enum dma_data_direction direction)
{
	dma_unmap_sg(dev, table->sgl, table->orig_nents, direction);
	table->nents = table->orig_nents;
}

static void dma_heap_sync_sgtable_for_cpu(struct device *dev,
					  struct sg_table *table,
					  enum dma_data_direction direction)
{
	dma_sync_sg_for_cpu(dev, table->sgl, table->orig_nents, direction);
}

static void dma_heap_sync_sgtable_for_device(struct device *dev,
					     struct sg_table *table,
					     enum dma_data_direction direction)
{
	dma_sync_sg_for_device(dev, table->sgl, table->orig_nents, direction);
}

static struct page *system_heap_buffer_page(struct system_heap_buffer *buffer,
					    unsigned long page_num)
{
	struct scatterlist *sg;
	int i;

	for_each_sg(buffer->sg_table.sgl, sg, buffer->sg_table.orig_nents, i) {
		unsigned long npages = sg->length >> PAGE_SHIFT;

		if (page_num < npages)
			return nth_page(sg_page(sg), page_num);
		page_num -= npages;
	}

	return NULL;
}

static struct sg_table *dup_sg_table(struct sg_table *table)
{
	struct sg_table *new_table;
	struct scatterlist *sg, *new_sg;
	int ret, i;

	new_table = kzalloc(sizeof(*new_table), GFP_KERNEL);
	if (!new_table)
		return ERR_PTR(-ENOMEM);

	ret = sg_alloc_table(new_table, table->orig_nents, GFP_KERNEL);
	if (ret) {
		kfree(new_table);
		return ERR_PTR(ret);
	}

	new_sg = new_table->sgl;
	for_each_sg(table->sgl, sg, table->orig_nents, i) {
		sg_set_page(new_sg, sg_page(sg), sg->length, sg->offset);
		new_sg = sg_next(new_sg);
	}

	return new_table;
}

static int system_heap_attach(struct dma_buf *dmabuf, struct device *dev,
			      struct dma_buf_attachment *attachment)
{
	struct system_heap_buffer *buffer = dmabuf->priv;
	struct dma_heap_attachment *a;

	a = kzalloc(sizeof(*a), GFP_KERNEL);
	if (!a)
		return -ENOMEM;

	a->table = dup_sg_table(&buffer->sg_table);
	if (IS_ERR(a->table)) {
		int ret = PTR_ERR(a->table);

		kfree(a);
		return ret;
	}

	a->dev = dev;
	INIT_LIST_HEAD(&a->list);
	a->mapped = false;
	attachment->priv = a;

	mutex_lock(&buffer->lock);
	list_add(&a->list, &buffer->attachments);
	mutex_unlock(&buffer->lock);

	return 0;
}

static void system_heap_detach(struct dma_buf *dmabuf,
			       struct dma_buf_attachment *attachment)
{
	struct system_heap_buffer *buffer = dmabuf->priv;
	struct dma_heap_attachment *a = attachment->priv;

	mutex_lock(&buffer->lock);
	list_del(&a->list);
	mutex_unlock(&buffer->lock);

	sg_free_table(a->table);
	kfree(a->table);
	kfree(a);
}

static struct sg_table *system_heap_map_dma_buf(
		struct dma_buf_attachment *attachment,
		enum dma_data_direction direction)
{
	struct dma_heap_attachment *a = attachment->priv;
	int ret;

	ret = dma_heap_map_sgtable(attachment->dev, a->table, direction);
	if (ret)
		return ERR_PTR(ret);

	a->mapped = true;
	return a->table;
}

static void system_heap_unmap_dma_buf(struct dma_buf_attachment *attachment,
				      struct sg_table *table,
				      enum dma_data_direction direction)
{
	struct dma_heap_attachment *a = attachment->priv;

	a->mapped = false;
	dma_heap_unmap_sgtable(attachment->dev, table, direction);
}

static int system_heap_dma_buf_begin_cpu_access(struct dma_buf *dmabuf,
						enum dma_data_direction direction)
{
	struct system_heap_buffer *buffer = dmabuf->priv;
	struct dma_heap_attachment *a;

	mutex_lock(&buffer->lock);
	if (buffer->vmap_cnt)
		invalidate_kernel_vmap_range(buffer->vaddr, buffer->len);

	list_for_each_entry(a, &buffer->attachments, list) {
		if (!a->mapped)
			continue;
		dma_heap_sync_sgtable_for_cpu(a->dev, a->table, direction);
	}
	mutex_unlock(&buffer->lock);

	return 0;
}

static int system_heap_dma_buf_end_cpu_access(struct dma_buf *dmabuf,
					      enum dma_data_direction direction)
{
	struct system_heap_buffer *buffer = dmabuf->priv;
	struct dma_heap_attachment *a;

	mutex_lock(&buffer->lock);
	if (buffer->vmap_cnt)
		flush_kernel_vmap_range(buffer->vaddr, buffer->len);

	list_for_each_entry(a, &buffer->attachments, list) {
		if (!a->mapped)
			continue;
		dma_heap_sync_sgtable_for_device(a->dev, a->table, direction);
	}
	mutex_unlock(&buffer->lock);

	return 0;
}

static void *system_heap_map_atomic(struct dma_buf *dmabuf,
				    unsigned long page_num)
{
	struct system_heap_buffer *buffer = dmabuf->priv;
	struct page *page = system_heap_buffer_page(buffer, page_num);

	if (!page)
		return NULL;

	return kmap_atomic(page);
}

static void system_heap_unmap_atomic(struct dma_buf *dmabuf,
				     unsigned long page_num, void *vaddr)
{
	kunmap_atomic(vaddr);
}

static void *system_heap_map(struct dma_buf *dmabuf, unsigned long page_num)
{
	struct system_heap_buffer *buffer = dmabuf->priv;
	struct page *page = system_heap_buffer_page(buffer, page_num);

	if (!page)
		return NULL;

	return kmap(page);
}

static void system_heap_unmap(struct dma_buf *dmabuf, unsigned long page_num,
			      void *vaddr)
{
	struct system_heap_buffer *buffer = dmabuf->priv;
	struct page *page = system_heap_buffer_page(buffer, page_num);

	if (!page)
		return;

	kunmap(page);
}

static int system_heap_mmap(struct dma_buf *dmabuf, struct vm_area_struct *vma)
{
	struct system_heap_buffer *buffer = dmabuf->priv;
	struct scatterlist *sg;
	unsigned long addr = vma->vm_start;
	unsigned long skip = vma->vm_pgoff;
	int i, ret;

	for_each_sg(buffer->sg_table.sgl, sg, buffer->sg_table.orig_nents, i) {
		unsigned long npages = sg->length >> PAGE_SHIFT;
		unsigned long j;

		for (j = 0; j < npages; j++) {
			struct page *page;

			if (skip) {
				skip--;
				continue;
			}

			page = nth_page(sg_page(sg), j);
			ret = remap_pfn_range(vma, addr, page_to_pfn(page),
					      PAGE_SIZE, vma->vm_page_prot);
			if (ret)
				return ret;

			addr += PAGE_SIZE;
			if (addr >= vma->vm_end)
				return 0;
		}
	}

	return 0;
}

static void *system_heap_do_vmap(struct system_heap_buffer *buffer)
{
	struct page **pages, **tmp;
	struct scatterlist *sg;
	unsigned long npages = PAGE_ALIGN(buffer->len) >> PAGE_SHIFT;
	void *vaddr;
	int i;

	pages = vmalloc(sizeof(*pages) * npages);
	if (!pages)
		return ERR_PTR(-ENOMEM);

	tmp = pages;
	for_each_sg(buffer->sg_table.sgl, sg, buffer->sg_table.orig_nents, i) {
		unsigned long j, sg_npages = sg->length >> PAGE_SHIFT;

		for (j = 0; j < sg_npages; j++) {
			WARN_ON(tmp - pages >= npages);
			*tmp++ = nth_page(sg_page(sg), j);
		}
	}

	vaddr = vmap(pages, npages, VM_MAP, PAGE_KERNEL);
	vfree(pages);
	if (!vaddr)
		return ERR_PTR(-ENOMEM);

	return vaddr;
}

static void *system_heap_vmap(struct dma_buf *dmabuf)
{
	struct system_heap_buffer *buffer = dmabuf->priv;
	void *vaddr;

	mutex_lock(&buffer->lock);
	if (buffer->vmap_cnt) {
		buffer->vmap_cnt++;
		vaddr = buffer->vaddr;
		goto out;
	}

	vaddr = system_heap_do_vmap(buffer);
	if (IS_ERR(vaddr)) {
		vaddr = ERR_CAST(vaddr);
		goto out;
	}

	buffer->vaddr = vaddr;
	buffer->vmap_cnt++;
out:
	mutex_unlock(&buffer->lock);
	return vaddr;
}

static void system_heap_vunmap(struct dma_buf *dmabuf, void *vaddr)
{
	struct system_heap_buffer *buffer = dmabuf->priv;

	mutex_lock(&buffer->lock);
	if (!--buffer->vmap_cnt) {
		vunmap(buffer->vaddr);
		buffer->vaddr = NULL;
	}
	mutex_unlock(&buffer->lock);
}

static void system_heap_dma_buf_release(struct dma_buf *dmabuf)
{
	struct system_heap_buffer *buffer = dmabuf->priv;
	struct scatterlist *sg;
	int i;

	for_each_sg(buffer->sg_table.sgl, sg, buffer->sg_table.orig_nents, i)
		__free_pages(sg_page(sg), compound_order(sg_page(sg)));

	sg_free_table(&buffer->sg_table);
	kfree(buffer);
}

static const struct dma_buf_ops system_heap_buf_ops = {
	.attach = system_heap_attach,
	.detach = system_heap_detach,
	.map_dma_buf = system_heap_map_dma_buf,
	.unmap_dma_buf = system_heap_unmap_dma_buf,
	.release = system_heap_dma_buf_release,
	.begin_cpu_access = system_heap_dma_buf_begin_cpu_access,
	.end_cpu_access = system_heap_dma_buf_end_cpu_access,
	.map_atomic = system_heap_map_atomic,
	.unmap_atomic = system_heap_unmap_atomic,
	.map = system_heap_map,
	.unmap = system_heap_unmap,
	.mmap = system_heap_mmap,
	.vmap = system_heap_vmap,
	.vunmap = system_heap_vunmap,
};

static struct page *alloc_largest_available(unsigned long size,
					    unsigned int max_order)
{
	struct page *page;
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(orders); i++) {
		if (size < (PAGE_SIZE << orders[i]))
			continue;
		if (max_order < orders[i])
			continue;

		page = alloc_pages(order_flags[i], orders[i]);
		if (page)
			return page;
	}

	return NULL;
}

static struct dma_buf *system_heap_allocate(struct dma_heap *heap,
					    unsigned long len,
					    unsigned long fd_flags,
					    unsigned long heap_flags)
{
	struct system_heap_buffer *buffer;
	struct sg_table *table;
	struct scatterlist *sg;
	unsigned long size_remaining = len;
	unsigned int max_order = orders[0];
	struct list_head pages;
	struct page *page, *tmp_page;
	struct dma_buf *dmabuf;
	int i, ret = -ENOMEM;

	buffer = kzalloc(sizeof(*buffer), GFP_KERNEL);
	if (!buffer)
		return ERR_PTR(-ENOMEM);

	INIT_LIST_HEAD(&buffer->attachments);
	mutex_init(&buffer->lock);
	buffer->heap = heap;
	buffer->len = len;

	INIT_LIST_HEAD(&pages);
	i = 0;
	while (size_remaining > 0) {
		if (fatal_signal_pending(current)) {
			ret = -EINTR;
			goto free_buffer;
		}

		page = alloc_largest_available(size_remaining, max_order);
		if (!page)
			goto free_buffer;

		list_add_tail(&page->lru, &pages);
		size_remaining -= PAGE_SIZE << compound_order(page);
		max_order = compound_order(page);
		i++;
	}

	table = &buffer->sg_table;
	ret = sg_alloc_table(table, i, GFP_KERNEL);
	if (ret)
		goto free_buffer;

	sg = table->sgl;
	list_for_each_entry_safe(page, tmp_page, &pages, lru) {
		sg_set_page(sg, page, PAGE_SIZE << compound_order(page), 0);
		sg = sg_next(sg);
		list_del(&page->lru);
	}

	DEFINE_DMA_BUF_EXPORT_INFO(exp_info);
	exp_info.exp_name = dma_heap_get_name(heap);
	exp_info.ops = &system_heap_buf_ops;
	exp_info.size = buffer->len;
	exp_info.flags = fd_flags;
	exp_info.priv = buffer;

	dmabuf = dma_buf_export(&exp_info);
	if (IS_ERR(dmabuf)) {
		ret = PTR_ERR(dmabuf);
		goto free_pages;
	}

	return dmabuf;

free_pages:
	for_each_sg(table->sgl, sg, table->orig_nents, i)
		__free_pages(sg_page(sg), compound_order(sg_page(sg)));
	sg_free_table(table);
free_buffer:
	list_for_each_entry_safe(page, tmp_page, &pages, lru)
		__free_pages(page, compound_order(page));
	kfree(buffer);
	return ERR_PTR(ret);
}

static const struct dma_heap_ops system_heap_ops = {
	.allocate = system_heap_allocate,
};

static int __init system_heap_create(void)
{
	struct dma_heap_export_info exp_info;

	exp_info.name = "system";
	exp_info.ops = &system_heap_ops;
	exp_info.priv = NULL;

	sys_heap = dma_heap_add(&exp_info);
	if (IS_ERR(sys_heap))
		return PTR_ERR(sys_heap);

	return 0;
}
module_init(system_heap_create);

MODULE_LICENSE("GPL v2");
