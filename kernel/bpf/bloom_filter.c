// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2021 Facebook */

#include <linux/bitmap.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/err.h>
#include <linux/jhash.h>
#include <linux/random.h>
#include <linux/slab.h>

#define BLOOM_CREATE_FLAG_MASK \
	(BPF_F_NUMA_NODE | BPF_F_ZERO_SEED | BPF_F_ACCESS_MASK)

struct bpf_bloom_filter {
	struct bpf_map map;
	u32 bitset_mask;
	u32 hash_seed;
	u32 nr_hash_funcs;
	unsigned long bitset[];
};

static u32 hash(struct bpf_bloom_filter *bloom, void *value,
		u32 value_size, u32 index)
{
	u32 h;

	if (likely(value_size % 4 == 0))
		h = jhash2(value, value_size / 4, bloom->hash_seed + index);
	else
		h = jhash(value, value_size, bloom->hash_seed + index);

	return h & bloom->bitset_mask;
}

/* Called from syscall */
static int bloom_map_alloc_check(union bpf_attr *attr)
{
	if (!bpf_capable())
		return -EPERM;

	if (attr->key_size != 0 || attr->value_size == 0 ||
	    attr->max_entries == 0 ||
	    attr->map_flags & ~BLOOM_CREATE_FLAG_MASK ||
	    !bpf_map_flags_access_ok(attr->map_flags) ||
	    (attr->map_extra & ~0xF))
		return -EINVAL;

	if (attr->value_size > KMALLOC_MAX_SIZE)
		return -E2BIG;

	return 0;
}

static int bloom_map_peek_elem(struct bpf_map *map, void *value)
{
	struct bpf_bloom_filter *bloom =
		container_of(map, struct bpf_bloom_filter, map);
	u32 i, h;

	for (i = 0; i < bloom->nr_hash_funcs; i++) {
		h = hash(bloom, value, map->value_size, i);
		if (!test_bit(h, bloom->bitset))
			return -ENOENT;
	}

	return 0;
}

static int bloom_map_push_elem(struct bpf_map *map, void *value, u64 flags)
{
	struct bpf_bloom_filter *bloom =
		container_of(map, struct bpf_bloom_filter, map);
	u32 i, h;

	if (flags != BPF_ANY)
		return -EINVAL;

	for (i = 0; i < bloom->nr_hash_funcs; i++) {
		h = hash(bloom, value, map->value_size, i);
		set_bit(h, bloom->bitset);
	}

	return 0;
}

static int bloom_map_pop_elem(struct bpf_map *map, void *value)
{
	return -EOPNOTSUPP;
}

static int bloom_map_delete_elem(struct bpf_map *map, void *key)
{
	return -EOPNOTSUPP;
}

static int bloom_map_get_next_key(struct bpf_map *map, void *key, void *next_key)
{
	return -EOPNOTSUPP;
}

static struct bpf_map *bloom_map_alloc(union bpf_attr *attr)
{
	u32 bitset_bytes, bitset_mask, nr_hash_funcs, nr_bits;
	int ret, numa_node = bpf_map_attr_numa_node(attr);
	struct bpf_map_memory mem = {0};
	struct bpf_bloom_filter *bloom;
	u64 cost;

	nr_hash_funcs = attr->map_extra & 0xF;
	if (nr_hash_funcs == 0)
		nr_hash_funcs = 5;

	/* Approximate 1 / ln(2) with 7 / 5. */
	if (check_mul_overflow(attr->max_entries, nr_hash_funcs, &nr_bits) ||
	    check_mul_overflow(nr_bits / 5, (u32)7, &nr_bits) ||
	    nr_bits > (1UL << 31)) {
		bitset_bytes = BITS_TO_LONGS(U32_MAX) * sizeof(unsigned long);
		bitset_mask = U32_MAX;
	} else {
		if (nr_bits <= BITS_PER_LONG)
			nr_bits = BITS_PER_LONG;
		else
			nr_bits = roundup_pow_of_two(nr_bits);
		bitset_bytes = BITS_TO_LONGS(nr_bits) * sizeof(unsigned long);
		bitset_mask = nr_bits - 1;
	}
	cost = sizeof(*bloom) + bitset_bytes;

	ret = bpf_map_charge_init(&mem, cost);
	if (ret < 0)
		return ERR_PTR(ret);

	bloom = bpf_map_area_alloc(cost, numa_node);
	if (!bloom) {
		bpf_map_charge_finish(&mem);
		return ERR_PTR(-ENOMEM);
	}

	bpf_map_init_from_attr(&bloom->map, attr);
	bpf_map_charge_move(&bloom->map.memory, &mem);

	bloom->nr_hash_funcs = nr_hash_funcs;
	bloom->bitset_mask = bitset_mask;

	if (!(attr->map_flags & BPF_F_ZERO_SEED))
		bloom->hash_seed = get_random_u32();

	return &bloom->map;
}

static void bloom_map_free(struct bpf_map *map)
{
	struct bpf_bloom_filter *bloom =
		container_of(map, struct bpf_bloom_filter, map);

	bpf_map_area_free(bloom);
}

static void *bloom_map_lookup_elem(struct bpf_map *map, void *key)
{
	/* eBPF programs must use bpf_map_peek_elem(). */
	return ERR_PTR(-EINVAL);
}

static int bloom_map_update_elem(struct bpf_map *map, void *key,
				 void *value, u64 flags)
{
	/* eBPF programs must use bpf_map_push_elem(). */
	return -EINVAL;
}

static int bloom_map_check_btf(const struct bpf_map *map,
			       const struct btf *btf,
			       const struct btf_type *key_type,
			       const struct btf_type *value_type)
{
	/* Bloom filter maps are keyless. */
	return btf_type_is_void(key_type) ? 0 : -EINVAL;
}

static int bpf_bloom_map_btf_id;
const struct bpf_map_ops bloom_filter_map_ops = {
	.map_meta_equal = bpf_map_meta_equal,
	.map_alloc_check = bloom_map_alloc_check,
	.map_alloc = bloom_map_alloc,
	.map_free = bloom_map_free,
	.map_get_next_key = bloom_map_get_next_key,
	.map_lookup_elem = bloom_map_lookup_elem,
	.map_update_elem = bloom_map_update_elem,
	.map_delete_elem = bloom_map_delete_elem,
	.map_push_elem = bloom_map_push_elem,
	.map_pop_elem = bloom_map_pop_elem,
	.map_peek_elem = bloom_map_peek_elem,
	.map_check_btf = bloom_map_check_btf,
	.map_btf_name = "bpf_bloom_filter",
	.map_btf_id = &bpf_bloom_map_btf_id,
};
