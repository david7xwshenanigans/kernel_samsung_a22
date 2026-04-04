/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Restartable sequences system call
 */

#include <linux/sched.h>
#include <linux/uaccess.h>
#include <linux/syscalls.h>
#include <linux/rseq.h>
#include <linux/types.h>

#include <asm/ptrace.h>

#define RSEQ_CS_PREEMPT_MIGRATE_FLAGS \
	(RSEQ_CS_FLAG_NO_RESTART_ON_MIGRATE | \
	 RSEQ_CS_FLAG_NO_RESTART_ON_PREEMPT)

static int rseq_update_cpu_id(struct task_struct *t)
{
	u32 cpu_id = raw_smp_processor_id();
	struct rseq __user *rseq = t->rseq;

	if (!user_access_begin(VERIFY_WRITE, rseq, sizeof(*rseq)))
		goto efault;
	unsafe_put_user(cpu_id, &rseq->cpu_id_start, efault_end);
	unsafe_put_user(cpu_id, &rseq->cpu_id, efault_end);
	user_access_end();
	return 0;

efault_end:
	user_access_end();
efault:
	return -EFAULT;
}

static int rseq_reset_rseq_cpu_id(struct task_struct *t)
{
	u32 cpu_id_start = 0, cpu_id = RSEQ_CPU_ID_UNINITIALIZED;

	if (put_user(cpu_id_start, &t->rseq->cpu_id_start))
		return -EFAULT;
	if (put_user(cpu_id, &t->rseq->cpu_id))
		return -EFAULT;
	return 0;
}

static int rseq_get_rseq_cs(struct task_struct *t, struct rseq_cs *rseq_cs)
{
	struct rseq_cs __user *urseq_cs;
	u64 ptr;
	u32 __user *usig;
	u32 sig;
	int ret;

	if (get_user(ptr, &t->rseq->rseq_cs.ptr64))
		return -EFAULT;
	if (!ptr) {
		memset(rseq_cs, 0, sizeof(*rseq_cs));
		return 0;
	}
	if (ptr >= TASK_SIZE)
		return -EINVAL;
	urseq_cs = (struct rseq_cs __user *)(unsigned long)ptr;
	if (copy_from_user(rseq_cs, urseq_cs, sizeof(*rseq_cs)))
		return -EFAULT;

	if (rseq_cs->start_ip >= TASK_SIZE ||
	    rseq_cs->start_ip + rseq_cs->post_commit_offset >= TASK_SIZE ||
	    rseq_cs->abort_ip >= TASK_SIZE ||
	    rseq_cs->version > 0)
		return -EINVAL;
	if (rseq_cs->start_ip + rseq_cs->post_commit_offset <
	    rseq_cs->start_ip)
		return -EINVAL;
	if (rseq_cs->abort_ip - rseq_cs->start_ip <
	    rseq_cs->post_commit_offset)
		return -EINVAL;

	usig = (u32 __user *)(unsigned long)(rseq_cs->abort_ip - sizeof(u32));
	ret = get_user(sig, usig);
	if (ret)
		return ret;

	if (current->rseq_sig != sig)
		return -EINVAL;
	return 0;
}

static int rseq_need_restart(struct task_struct *t, u32 cs_flags)
{
	u32 flags, event_mask;
	int ret;

	ret = get_user(flags, &t->rseq->flags);
	if (ret)
		return ret;

	flags |= cs_flags;

	if ((flags & RSEQ_CS_FLAG_NO_RESTART_ON_SIGNAL) &&
	    (flags & RSEQ_CS_PREEMPT_MIGRATE_FLAGS) !=
	    RSEQ_CS_PREEMPT_MIGRATE_FLAGS)
		return -EINVAL;

	preempt_disable();
	event_mask = t->rseq_event_mask;
	t->rseq_event_mask = 0;
	preempt_enable();

	return !!(event_mask & ~flags);
}

static int clear_rseq_cs(struct task_struct *t)
{
	return put_user(0UL, &t->rseq->rseq_cs.ptr64);
}

static bool in_rseq_cs(unsigned long ip, struct rseq_cs *rseq_cs)
{
	return ip - rseq_cs->start_ip < rseq_cs->post_commit_offset;
}

static int rseq_ip_fixup(struct pt_regs *regs)
{
	unsigned long ip = instruction_pointer(regs);
	struct task_struct *t = current;
	struct rseq_cs rseq_cs;
	int ret;

	ret = rseq_get_rseq_cs(t, &rseq_cs);
	if (ret)
		return ret;

	if (!in_rseq_cs(ip, &rseq_cs))
		return clear_rseq_cs(t);
	ret = rseq_need_restart(t, rseq_cs.flags);
	if (ret <= 0)
		return ret;
	ret = clear_rseq_cs(t);
	if (ret)
		return ret;
	instruction_pointer_set(regs, (unsigned long)rseq_cs.abort_ip);
	return 0;
}

void __rseq_handle_notify_resume(struct ksignal *ksig, struct pt_regs *regs)
{
	struct task_struct *t = current;
	int ret, sig;

	if (unlikely(t->flags & PF_EXITING))
		return;

	if (regs) {
		ret = rseq_ip_fixup(regs);
		if (unlikely(ret < 0))
			goto error;
	}
	if (unlikely(rseq_update_cpu_id(t)))
		goto error;
	return;

error:
	sig = ksig ? ksig->sig : 0;
	force_sigsegv(sig, current);
}

SYSCALL_DEFINE4(rseq, struct rseq __user *, rseq, u32, rseq_len,
		int, flags, u32, sig)
{
	int ret;

	if (flags & RSEQ_FLAG_UNREGISTER) {
		if (flags & ~RSEQ_FLAG_UNREGISTER)
			return -EINVAL;
		if (current->rseq != rseq || !current->rseq)
			return -EINVAL;
		if (rseq_len != sizeof(*rseq))
			return -EINVAL;
		if (current->rseq_sig != sig)
			return -EPERM;
		ret = rseq_reset_rseq_cpu_id(current);
		if (ret)
			return ret;
		current->rseq = NULL;
		current->rseq_sig = 0;
		return 0;
	}

	if (unlikely(flags))
		return -EINVAL;

	if (current->rseq) {
		if (current->rseq != rseq || rseq_len != sizeof(*rseq))
			return -EINVAL;
		if (current->rseq_sig != sig)
			return -EPERM;
		return -EBUSY;
	}

	if (!IS_ALIGNED((unsigned long)rseq, __alignof__(*rseq)) ||
	    rseq_len != sizeof(*rseq))
		return -EINVAL;
	if (!access_ok(VERIFY_WRITE, rseq, rseq_len))
		return -EFAULT;
	current->rseq = rseq;
	current->rseq_sig = sig;
	rseq_set_notify_resume(current);

	return 0;
}
