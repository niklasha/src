/*	$OpenBSD: vm.c,v 1.124 2026/02/18 22:28:19 dv Exp $	*/

/*
 * Copyright (c) 2015 Mike Larkin <mlarkin@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/param.h>	/* PAGE_SIZE, MAXCOMLEN */
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/resource.h>

#include <dev/vmm/vmm.h>

#include <errno.h>
#include <event.h>
#include <fcntl.h>
#include <imsg.h>
#include <poll.h>
#include <pthread.h>
#include <pthread_np.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <util.h>

#include "atomicio.h"
#include "pci.h"
#include "virtio.h"
#include "vmd.h"

/*
 * Seconds to wait for all vcpu threads to exit after the VM is known to be
 * terminating before the per-VM process force-exits (suicide watchdog).
 */
#define VM_TERMINATE_TIMEOUT_SEC 3

static int run_vm(struct vmd_vm *, struct vcpu_reg_state *);
static void vm_dispatch_vmm(int, short, void *);
static void *event_thread(void *);
static void *vcpu_run_loop(void *);
static void vm_set_terminating(void);
static int vmm_create_vm(struct vmd_vm *);
static void pause_vm(struct vmd_vm *);
static void unpause_vm(struct vmd_vm *);
static int start_vm(struct vmd_vm *, int);

int con_fd;
struct vmd_vm *current_vm;

extern struct vmd *env;
extern __thread uint32_t current_vcpu_id;

pthread_mutex_t threadmutex;
pthread_cond_t threadcond;

pthread_cond_t vcpu_run_cond[VMM_MAX_VCPUS_PER_VM];
pthread_mutex_t vcpu_run_mtx[VMM_MAX_VCPUS_PER_VM];
pthread_barrier_t vm_pause_barrier;
pthread_cond_t vcpu_unpause_cond[VMM_MAX_VCPUS_PER_VM];
pthread_mutex_t vcpu_unpause_mtx[VMM_MAX_VCPUS_PER_VM];

pthread_mutex_t vm_mtx;
uint8_t vcpu_hlt[VMM_MAX_VCPUS_PER_VM];
uint8_t vcpu_done[VMM_MAX_VCPUS_PER_VM];

/*
 * Set once the kernel vm object is gone (force-stop / guest terminated).
 * Written under vm_mtx by vm_set_terminating(); read both under vm_mtx
 * (reaper) and as a lock-free fast path (vcpu_run_loop top).  Once set, every
 * vcpu thread must stop spinning and exit so the per-VM process can die
 * instead of orphaning.
 */
volatile sig_atomic_t vm_terminating;

/*
 * vm_main
 *
 * Primary entrypoint for launching a vm. Does not return.
 *
 * fd: file descriptor for communicating with vmm process.
 * fd_vmm: file descriptor for communicating with vmm(4) device
 */
void
vm_main(int fd, int fd_vmm)
{
	struct vmd_vm		 vm;
	size_t			 sz = 0;
	int			 ret = 0;

	/*
	 * The vm process relies on global state. Set the fd for /dev/vmm.
	 */
	env->vmd_fd = fd_vmm;

	/*
	 * We aren't root, so we can't chroot(2). Use unveil(2) instead.
	 */
	if (unveil(env->argv0, "x") == -1)
		fatal("unveil %s", env->argv0);
	if (unveil(NULL, NULL) == -1)
		fatal("unveil lock");

	/*
	 * pledge in the vm processes:
	 * stdio - for malloc and basic I/O including events.
	 * vmm - for the vmm ioctls and operations.
	 * proc exec - fork/exec for launching devices.
	 */
	if (pledge("stdio vmm proc exec", NULL) == -1)
		fatal("pledge");

	/* Receive our vm configuration. */
	memset(&vm, 0, sizeof(vm));
	sz = atomicio(read, fd, &vm, sizeof(vm));
	if (sz != sizeof(vm)) {
		log_warnx("failed to receive start message");
		_exit(EIO);
	}

	/* Update process with the vm name. */
	setproctitle("%s", vm.vm_params.vmc_name);
	log_procinit("vm/%s", vm.vm_params.vmc_name);

	/* Receive the local prefix settings. */
	sz = atomicio(read, fd, &env->vmd_cfg.cfg_localprefix,
	    sizeof(env->vmd_cfg.cfg_localprefix));
	if (sz != sizeof(env->vmd_cfg.cfg_localprefix)) {
		log_warnx("failed to receive local prefix");
		_exit(EIO);
	}

	/*
	 * We need, at minimum, a vm_kernel fd to boot a vm. This is either a
	 * kernel or a BIOS image.
	 */
	if (vm.vm_kernel == -1) {
		log_warnx("failed to receive boot fd");
		_exit(EINVAL);
	}

	if (vm.vm_params.vmc_sev && env->vmd_psp_fd < 0) {
		log_warnx("%s not available", PSP_NODE);
		_exit(EINVAL);
	}

	ret = start_vm(&vm, fd);
	_exit(ret);
}

/*
 * start_vm
 *
 * After forking a new VM process, starts the new VM with the creation
 * parameters supplied (in the incoming vm->vm_params field). This
 * function performs a basic sanity check on the incoming parameters
 * and then performs the following steps to complete the creation of the VM:
 *
 * 1. validates and create the new VM
 * 2. opens the imsg control channel to the parent and drops more privilege
 * 3. drops additional privileges by calling pledge(2)
 * 4. loads the kernel from the disk image or file descriptor
 * 5. runs the VM's VCPU loops.
 *
 * Parameters:
 *  vm: The VM data structure that is including the VM create parameters.
 *  fd: The imsg socket that is connected to the parent process.
 *
 * Return values:
 *  0: success
 *  !0 : failure - typically an errno indicating the source of the failure
 */
int
start_vm(struct vmd_vm *vm, int fd)
{
	struct vcpu_reg_state	 vrs;
	int			 ret, nicfds[VM_MAX_NICS_PER_VM];
	size_t			 i;

	/*
	 * We first try to initialize and allocate memory before bothering
	 * vmm(4) with a request to create a new vm.
	 */
	create_memory_map(vm);

	/* Create the vm in vmm(4). */
	ret = vmm_create_vm(vm);
	if (ret) {
		struct rlimit lim;
		char buf[FMT_SCALED_STRSIZE];
		if (ret == ENOMEM && getrlimit(RLIMIT_DATA, &lim) == 0) {
			if (fmt_scaled(lim.rlim_cur, buf) == 0)
				fatalx("could not allocate guest memory (data "
				    "limit is %s)", buf);
		} else {
			errno = ret;
			log_warn("could not create vm");
		}

		/* Let the vmm process know we failed by sending a 0 vm id. */
		vm->vm_vmmid = 0;
		atomicio(vwrite, fd, &vm->vm_vmmid, sizeof(vm->vm_vmmid));
		return (ret);
	}

	/* Setup SEV. */
	ret = sev_init(vm);
	if (ret) {
		log_warnx("could not initialize SEV");
		return (ret);
	}

	/*
	 * Some of vmd currently relies on global state (current_vm, con_fd).
	 */
	current_vm = vm;
	con_fd = vm->vm_tty;
	if (fcntl(con_fd, F_SETFL, O_NONBLOCK) == -1) {
		log_warn("failed to set nonblocking mode on console");
		return (1);
	}

	/*
	 * We now let the vmm process know we were successful by sending it our
	 * vmm(4) assigned vm id.
	 */
	if (atomicio(vwrite, fd, &vm->vm_vmmid, sizeof(vm->vm_vmmid)) !=
	    sizeof(vm->vm_vmmid)) {
		log_warn("failed to send created vm id to vmm process");
		return (1);
	}

	/* Prepare our boot image. */
	if (load_firmware(vm, &vrs))
		fatalx("failed to load kernel or firmware image");

	if (vm->vm_kernel != -1)
		close_fd(vm->vm_kernel);

	/* Initialize our mutexes. */
	ret = pthread_mutex_init(&threadmutex, NULL);
	if (ret) {
		log_warn("%s: could not initialize thread state mutex",
		    __func__);
		return (ret);
	}
	ret = pthread_cond_init(&threadcond, NULL);
	if (ret) {
		log_warn("%s: could not initialize thread state "
		    "condition variable", __func__);
		return (ret);
	}
	ret = pthread_mutex_init(&vm_mtx, NULL);
	if (ret) {
		log_warn("%s: could not initialize vm state mutex",
		    __func__);
		return (ret);
	}

	/* Lock thread mutex now. It's unlocked when waiting on threadcond. */
	mutex_lock(&threadmutex);

	/*
	 * Finalize our communication socket with the vmm process. From here
	 * onwards, communication with the vmm process is event-based.
	 */
	event_init();
	if (vmm_pipe(vm, fd, vm_dispatch_vmm) == -1)
		fatal("setup vm pipe");

	/*
	 * Initialize our emulated hardware.
	 */
	for (i = 0; i < VMM_MAX_NICS_PER_VM; i++)
		nicfds[i] = vm->vm_ifs[i].vif_fd;
	ret = init_emulated_hw(vm, vm->vm_cdrom, vm->vm_disks, nicfds);
	if (ret) {
		virtio_shutdown(vm);
		return (ret);
	}

	/* Drop privleges further before starting the vcpu run loop(s). */
	if (pledge("stdio vmm", NULL) == -1)
		fatal("pledge");

	/*
	 * Execute the vcpu run loop(s) for this VM.
	 */
	ret = run_vm(vm, &vrs);

	/* Shutdown SEV. */
	if (sev_shutdown(vm))
		log_warnx("%s: could not shutdown SEV", __func__);

	/* Ensure that any in-flight data is written back */
	virtio_shutdown(vm);

	return (ret);
}

/*
 * vm_dispatch_vmm
 *
 * imsg callback for messages that are received from the vmm parent process.
 */
void
vm_dispatch_vmm(int fd, short event, void *arg)
{
	struct vmd_vm		*vm = arg;
	struct vmop_result	 vmr;
	struct vmop_addr_result	 var;
	struct imsgev		*iev = &vm->vm_iev;
	struct imsgbuf		*ibuf = &iev->ibuf;
	struct imsg		 imsg;
	uint32_t		 id, type;
	pid_t			 pid;
	ssize_t			 n;
	int			 verbose;

	if (event & EV_READ) {
		if ((n = imsgbuf_read(ibuf)) == -1)
			fatal("%s: imsgbuf_read", __func__);
		if (n == 0)
			_exit(0);
	}

	if (event & EV_WRITE) {
		if (imsgbuf_write(ibuf) == -1) {
			if (errno == EPIPE)
				_exit(0);
			fatal("%s: imsgbuf_write fd %d", __func__, ibuf->fd);
		}
	}

	for (;;) {
		if ((n = imsg_get(ibuf, &imsg)) == -1)
			fatal("%s: imsg_get", __func__);
		if (n == 0)
			break;

		type = imsg_get_type(&imsg);
		id = imsg_get_id(&imsg);
		pid = imsg_get_pid(&imsg);
#if DEBUG > 1
		log_debug("%s: got imsg %d from %s", __func__, type,
		    vm->vm_params.vmc_params.vcp_name);
#endif

		switch (type) {
		case IMSG_CTL_VERBOSE:
			verbose = imsg_int_read(&imsg);
			log_setverbose(verbose);
			virtio_broadcast_imsg(vm, IMSG_CTL_VERBOSE, &verbose,
			    sizeof(verbose));
			break;
		case IMSG_VMDOP_VM_SHUTDOWN:
			if (vmmci_ctl(&vmmci, VMMCI_SHUTDOWN) == -1) {
				/*
				 * Guest has no vmmci driver (e.g. Linux), so
				 * the graceful request was a no-op and we exit
				 * now.  Quiesce the vcpu threads first:
				 * pause_vm drives them out of
				 * ioctl(VMM_IOC_RUN) to the pause barrier
				 * (userspace), so the subsequent _exit ->
				 * uvm_map_teardown does not race a sibling vcpu
				 * still inside uvm_fault_wire on the shared
				 * guest-memory map -- that race strands a wired
				 * PG_PVLIST PTE on a freed page and panics the
				 * host (pmap_remove_ptes: unmanaged page marked
				 * PG_PVLIST).  Only exposed once cpus>1 was
				 * allowed.
				 */
				pause_vm(vm);
				_exit(0);
			}
			break;
		case IMSG_VMDOP_VM_REBOOT:
			if (vmmci_ctl(&vmmci, VMMCI_REBOOT) == -1) {
				pause_vm(vm);
				_exit(0);
			}
			break;
		case IMSG_VMDOP_VM_TERMINATE:
			/*
			 * Operator force-stop (vmctl stop -f): PROC_VMM is
			 * destroying the kernel VM object.  Set the terminate
			 * flag directly rather than waiting for a vcpu to
			 * discover ENOENT on its own -- this wakes any halted
			 * vcpus (broadcast) so they exit, and arms the reaper's
			 * bounded suicide watchdog, so the process cannot
			 * orphan in "stopping" when no vcpu happens to be in
			 * ioctl(VMM_IOC_RUN) to see the VM vanish.
			 */
			vm_set_terminating();
			break;
		case IMSG_VMDOP_PAUSE_VM:
			vmr.vmr_result = 0;
			vmr.vmr_id = vm->vm_vmid;
			pause_vm(vm);
			imsg_compose_event(&vm->vm_iev,
			    IMSG_VMDOP_PAUSE_VM_RESPONSE, id, pid, -1, &vmr,
			    sizeof(vmr));
			break;
		case IMSG_VMDOP_UNPAUSE_VM:
			vmr.vmr_result = 0;
			vmr.vmr_id = vm->vm_vmid;
			unpause_vm(vm);
			imsg_compose_event(&vm->vm_iev,
			    IMSG_VMDOP_UNPAUSE_VM_RESPONSE, id, pid, -1, &vmr,
			    sizeof(vmr));
			break;
		case IMSG_VMDOP_PRIV_GET_ADDR_RESPONSE:
			vmop_addr_result_read(&imsg, &var);
			log_debug("%s: received tap addr %s for nic %d",
			    vm->vm_params.vmc_name,
			    ether_ntoa((void *)var.var_addr), var.var_nic_idx);

			vionet_set_hostmac(vm, var.var_nic_idx, var.var_addr);
			break;
		default:
			fatalx("%s: got invalid imsg %d from %s", __func__,
			    type, vm->vm_params.vmc_name);
		}
		imsg_free(&imsg);
	}
	imsg_event_add(iev);
}

/*
 * vm_shutdown
 *
 * Tell the vmm parent process to shutdown or reboot the VM and exit.
 */
__dead void
vm_shutdown(unsigned int cmd)
{
	switch (cmd) {
	case VMMCI_NONE:
	case VMMCI_SHUTDOWN:
		(void)imsg_compose_event(&current_vm->vm_iev,
		    IMSG_VMDOP_VM_SHUTDOWN, 0, 0, -1, NULL, 0);
		break;
	case VMMCI_REBOOT:
		(void)imsg_compose_event(&current_vm->vm_iev,
		    IMSG_VMDOP_VM_REBOOT, 0, 0, -1, NULL, 0);
		break;
	default:
		fatalx("invalid vm ctl command: %d", cmd);
	}
	imsgbuf_flush(&current_vm->vm_iev.ibuf);

	if (sev_shutdown(current_vm))
		log_warnx("%s: could not shutdown SEV", __func__);

	_exit(0);
}

static void
pause_vm(struct vmd_vm *vm)
{
	unsigned int n;
	int ret;

	mutex_lock(&vm_mtx);
	if (vm->vm_state & VM_STATE_PAUSED) {
		mutex_unlock(&vm_mtx);
		return;
	}
	current_vm->vm_state |= VM_STATE_PAUSED;
	mutex_unlock(&vm_mtx);

	/*
	 * Broadcast under vcpu_run_mtx[n] so the wakeup orders against
	 * vcpu_run_loop()'s locked predicate check before it waits on
	 * vcpu_run_cond[n]; an unlocked broadcast can be missed by a vcpu
	 * just entering the wait (lost wakeup), so it never reaches the
	 * pause barrier and pause_vm() hangs.  Same fix as
	 * vm_set_terminating().
	 */
	for (n = 0; n < vm->vm_params.vmc_ncpus; n++) {
		mutex_lock(&vcpu_run_mtx[n]);
		ret = pthread_cond_broadcast(&vcpu_run_cond[n]);
		mutex_unlock(&vcpu_run_mtx[n]);
		if (ret) {
			log_warnx("%s: can't broadcast vcpu run cond (%d)",
			    __func__, (int)ret);
			return;
		}
	}
	ret = pthread_barrier_wait(&vm_pause_barrier);
	if (ret != 0 && ret != PTHREAD_BARRIER_SERIAL_THREAD) {
		log_warnx("%s: could not wait on pause barrier (%d)",
		    __func__, (int)ret);
		return;
	}

	pause_vm_md(vm);
}

static void
unpause_vm(struct vmd_vm *vm)
{
	unsigned int n;
	int ret;

	mutex_lock(&vm_mtx);
	if (!(vm->vm_state & VM_STATE_PAUSED)) {
		mutex_unlock(&vm_mtx);
		return;
	}
	current_vm->vm_state &= ~VM_STATE_PAUSED;
	mutex_unlock(&vm_mtx);

	/* Broadcast under vcpu_unpause_mtx[n] to avoid the same lost wakeup. */
	for (n = 0; n < vm->vm_params.vmc_ncpus; n++) {
		mutex_lock(&vcpu_unpause_mtx[n]);
		ret = pthread_cond_broadcast(&vcpu_unpause_cond[n]);
		mutex_unlock(&vcpu_unpause_mtx[n]);
		if (ret) {
			log_warnx("%s: can't broadcast vcpu unpause cond (%d)",
			    __func__, (int)ret);
			return;
		}
	}

	unpause_vm_md(vm);
}

/*
 * vcpu_reset
 *
 * Requests vmm(4) to reset the VCPUs in the indicated VM to
 * the register state provided
 *
 * Parameters
 *  vmid: VM ID to reset
 *  vcpu_id: VCPU ID to reset
 *  vrs: the register state to initialize
 *
 * Return values:
 *  0: success
 *  !0 : ioctl to vmm(4) failed (eg, ENOENT if the supplied VM ID is not
 *      valid)
 */
int
vcpu_reset(uint32_t vmid, uint32_t vcpu_id, struct vcpu_reg_state *vrs)
{
	struct vm_resetcpu_params vrp;

	memset(&vrp, 0, sizeof(vrp));
	vrp.vrp_vm_id = vmid;
	vrp.vrp_vcpu_id = vcpu_id;
	memcpy(&vrp.vrp_init_state, vrs, sizeof(struct vcpu_reg_state));

	log_debug("%s: resetting vcpu %d for vm %d", __func__, vcpu_id, vmid);

	if (ioctl(env->vmd_fd, VMM_IOC_RESETCPU, &vrp) == -1)
		return (errno);

	return (0);
}

/*
 * vmm_create_vm
 *
 * Requests vmm(4) to create a new VM using the supplied creation
 * parameters. This operation results in the creation of the in-kernel
 * structures for the VM, but does not start the VM's vcpu(s).
 *
 * Parameters:
 *  vm: pointer to the vm object
 *
 * Return values:
 *  0: success
 *  !0 : ioctl to vmm(4) failed
 */
static int
vmm_create_vm(struct vmd_vm *vm)
{
	struct vm_create_params		 vcp;
	struct vmop_create_params	*vmc = &vm->vm_params;
	size_t				 i;

	/* Sanity check arguments */
	if (vmc->vmc_ncpus > VMM_MAX_VCPUS_PER_VM)
		return (EINVAL);

	if (vmc->vmc_nmemranges == 0 ||
	    vmc->vmc_nmemranges > VMM_MAX_MEM_RANGES)
		return (EINVAL);

	if (vmc->vmc_ndisks > VM_MAX_DISKS_PER_VM)
		return (EINVAL);

	if (vmc->vmc_nnics > VM_MAX_NICS_PER_VM)
		return (EINVAL);

	memset(&vcp, 0, sizeof(vcp));
	vcp.vcp_nmemranges = vmc->vmc_nmemranges;
	vcp.vcp_ncpus = vmc->vmc_ncpus;
	memcpy(vcp.vcp_memranges, vmc->vmc_memranges,
	    sizeof(vcp.vcp_memranges));
	memcpy(vcp.vcp_name, vmc->vmc_name, sizeof(vcp.vcp_name));
	vcp.vcp_sev = vmc->vmc_sev;
	vcp.vcp_seves = vmc->vmc_seves;

	if (ioctl(env->vmd_fd, VMM_IOC_CREATE, &vcp) == -1)
		return (errno);

	vm->vm_vmmid = vcp.vcp_id;
	for (i = 0; i < vcp.vcp_ncpus; i++)
		vm->vm_sev_asid[i] = vcp.vcp_asid[i];
	for (i = 0; i < vmc->vmc_nmemranges; i++)
		vmc->vmc_memranges[i].vmr_va = vcp.vcp_memranges[i].vmr_va;
	vm->vm_poscbit = vcp.vcp_poscbit;

	return (0);
}


/*
 * run_vm
 *
 * Runs the VM whose creation parameters are specified in vcp
 *
 * Parameters:
 *  vm:  vm to begin emulating
 *  vrs: VCPU register state to initialize
 *
 * Return values:
 *  0: the VM exited normally
 *  !0 : the VM exited abnormally or failed to start
 */
static int
run_vm(struct vmd_vm *vm, struct vcpu_reg_state *vrs)
{
	struct vmop_create_params *vmc;
	uint8_t evdone = 0;
	size_t i, joined;
	int ret;
	pthread_t *tid, evtid;
	char tname[MAXCOMLEN + 1];
	struct vm_run_params **vrp;
	void *exit_status;

	vmc = &vm->vm_params;

	if (vmc->vmc_nmemranges == 0 ||
	    vmc->vmc_nmemranges > VMM_MAX_MEM_RANGES)
		return (EINVAL);

	tid = calloc(vmc->vmc_ncpus, sizeof(pthread_t));
	if (tid == NULL) {
		log_warn("failed to allocate pthread structures");
		return (ENOMEM);
	}
	vrp = calloc(vmc->vmc_ncpus, sizeof(struct vm_run_params *));
	if (vrp == NULL) {
		log_warn("failed to allocate vm run params array");
		return (ENOMEM);
	}

	ret = pthread_barrier_init(&vm_pause_barrier, NULL, vmc->vmc_ncpus + 1);
	if (ret) {
		log_warnx("cannot initialize pause barrier (%d)", ret);
		return (ret);
	}

	log_debug("%s: starting %zu vcpu thread(s) for vm %s", __func__,
	    vmc->vmc_ncpus, vmc->vmc_name);

	/* LAPIC/IOAPIC MMIO handlers for SMP and MP-kernel guests. */
	if (lapic_smp_init(vm->vm_vmmid, vmc->vmc_ncpus) != 0)
		log_warnx("%s: lapic_smp_init failed (continuing)",
		    __func__);

	/*
	 * Create and launch one thread for each VCPU. These threads may
	 * migrate between PCPUs over time; the need to reload CPU state
	 * in such situations is detected and performed by vmm(4) in the
	 * kernel.
	 */
	for (i = 0 ; i < vmc->vmc_ncpus; i++) {
		vrp[i] = malloc(sizeof(struct vm_run_params));
		if (vrp[i] == NULL) {
			log_warn("failed to allocate vm run parameters");
			/* caller will exit, so skip freeing */
			return (ENOMEM);
		}
		vrp[i]->vrp_exit = malloc(sizeof(struct vm_exit));
		if (vrp[i]->vrp_exit == NULL) {
			log_warn("failed to allocate vm exit area");
			/* caller will exit, so skip freeing */
			return (ENOMEM);
		}
		vrp[i]->vrp_vm_id = vm->vm_vmmid;
		vrp[i]->vrp_vcpu_id = i;

		if (vcpu_reset(vm->vm_vmmid, i, vrs)) {
			log_warnx("cannot reset vcpu %zu (vmmid=%u)",
			    i, vm->vm_vmmid);
			return (EIO);
		}

		if (sev_activate(vm, i)) {
			log_warnx("SEV activatation failed for vcpu %zu", i);
			return (EIO);
		}

		if (sev_encrypt_memory(vm)) {
			log_warnx("memory encryption failed for vcpu %zu", i);
			return (EIO);
		}

		if (sev_encrypt_state(vm, i)) {
			log_warnx("state encryption failed for vcpu %zu", i);
			return (EIO);
		}

		if (sev_launch_finalize(vm)) {
			log_warnx("encryption failed for vcpu %zu", i);
			return (EIO);
		}

		ret = pthread_cond_init(&vcpu_run_cond[i], NULL);
		if (ret) {
			log_warnx("cannot initialize cond var (%d)", ret);
			return (ret);
		}

		ret = pthread_mutex_init(&vcpu_run_mtx[i], NULL);
		if (ret) {
			log_warnx("cannot initialize mtx (%d)", ret);
			return (ret);
		}

		ret = pthread_cond_init(&vcpu_unpause_cond[i], NULL);
		if (ret) {
			log_warnx("cannot initialize unpause var (%d)", ret);
			return (ret);
		}

		ret = pthread_mutex_init(&vcpu_unpause_mtx[i], NULL);
		if (ret) {
			log_warnx("cannot initialize unpause mtx (%d)", ret);
			return (ret);
		}

		/*
		 * APs start halted; INIT/SIPI from BSP's LAPIC ICR wakes them.
		 */
		vcpu_hlt[i] = (i == 0) ? 0 : 1;

		/* Start each VCPU run thread at vcpu_run_loop */
		ret = pthread_create(&tid[i], NULL, vcpu_run_loop, vrp[i]);
		if (ret) {
			/* caller will _exit after this return */
			ret = errno;
			log_warn("%s: could not create vcpu thread %zu",
			    __func__, i);
			return (ret);
		}

		snprintf(tname, sizeof(tname), "vcpu-%zu", i);
		pthread_set_name_np(tid[i], tname);
	}

	log_debug("%s: waiting on events for VM %s", __func__, vmc->vmc_name);
	ret = pthread_create(&evtid, NULL, event_thread, &evdone);
	if (ret) {
		errno = ret;
		log_warn("%s: could not create event thread", __func__);
		return (ret);
	}
	pthread_set_name_np(evtid, "event");

	/* Timer thread must start after vcpu threads (kernel state). */
	if (vmc->vmc_ncpus > 1) {
		if (lapic_smp_timer_start() != 0)
			log_warnx("%s: lapic_smp_timer_start failed",
			    __func__);
	}

	joined = 0;
	while (joined < vmc->vmc_ncpus) {
		pthread_t to_join[VMM_MAX_VCPUS_PER_VM];
		size_t n_join = 0, k;
		int terminating;

		/*
		 * Harvest the vcpu threads that have exited since the last
		 * pass, clearing tid[] so each is joined exactly once.  This
		 * runs under vm_mtx (which an exiting thread also holds when it
		 * sets vcpu_done[]), but the pthread_join() itself must NOT run
		 * while we hold threadmutex: a vcpu takes threadmutex to signal
		 * threadcond right after setting vcpu_done[] (see
		 * vcpu_run_loop's exit path), so joining it under threadmutex
		 * would deadlock -- the reaper would wait for the thread to
		 * exit while the thread waits for threadmutex the reaper holds.
		 */
		mutex_lock(&vm_mtx);
		terminating = vm_terminating;
		for (i = 0; i < vmc->vmc_ncpus; i++) {
			if (vcpu_done[i] == 0 || tid[i] == NULL)
				continue;
			to_join[n_join++] = tid[i];
			tid[i] = NULL;
		}
		mutex_unlock(&vm_mtx);

		if (n_join == 0 && !evdone) {
			/*
			 * Nothing to reap yet: wait for the next thread to
			 * exit.  We still hold threadmutex, which the cond wait
			 * releases atomically; because we re-checked the
			 * predicate (vcpu_done[]/evdone) above while holding
			 * it, an exiting thread that has set its predicate but
			 * is blocked taking threadmutex to signal cannot be
			 * missed -- it signals only once we are actually
			 * waiting.
			 */
			if (terminating) {
				/*
				 * The VM is going away: bound how long we
				 * wait for the vcpu threads to exit.  If one is
				 * wedged (stuck in the kernel, or a device
				 * subprocess will not drain), force the process
				 * down rather than orphan forever.
				 */
				struct timespec ts;

				clock_gettime(CLOCK_REALTIME, &ts);
				ts.tv_sec += VM_TERMINATE_TIMEOUT_SEC;
				ret = pthread_cond_timedwait(&threadcond,
				    &threadmutex, &ts);
				if (ret == ETIMEDOUT) {
					log_warnx("%s: vcpu threads still "
					    "running %d s after termination "
					    "(%zu/%zu joined); forcing exit",
					    __func__, VM_TERMINATE_TIMEOUT_SEC,
					    joined, vmc->vmc_ncpus);
					_exit(0);
				}
			} else
				ret = pthread_cond_wait(&threadcond,
				    &threadmutex);

			if (ret && ret != ETIMEDOUT) {
				log_warn("%s: waiting on thread state "
				    "condition variable failed", __func__);
				mutex_unlock(&threadmutex);
				return (ret);
			}
			continue;
		}

		/*
		 * Join the harvested threads with threadmutex released so each
		 * can take it to signal threadcond and finish.
		 */
		mutex_unlock(&threadmutex);
		for (k = 0; k < n_join; k++) {
			if (pthread_join(to_join[k], &exit_status)) {
				log_warn("failed to join vcpu thread");
				return (EIO);
			}
			joined++;
			ret = (intptr_t)exit_status;
		}

		/* Did the event thread exit? => return with an error */
		if (evdone) {
			if (pthread_join(evtid, &exit_status)) {
				log_warn("failed to join event thread");
				return (EIO);
			}

			log_warnx("event thread exited unexpectedly");
			return (EIO);
		}

		mutex_lock(&threadmutex);
	}
	mutex_unlock(&threadmutex);

	lapic_smp_timer_stop();
	lapic_smp_free();

	if (pthread_barrier_destroy(&vm_pause_barrier))
		log_warnx("could not destroy pause barrier");

	return (ret);
}

static void *
event_thread(void *arg)
{
	uint8_t *donep = arg;
	intptr_t ret;

	ret = event_dispatch();

	*donep = 1;

	mutex_lock(&threadmutex);
	pthread_cond_signal(&threadcond);
	mutex_unlock(&threadmutex);

	return (void *)ret;
 }

/*
 * vm_set_terminating
 *
 * Mark the VM as going away (the kernel vm object was destroyed -- e.g. by a
 * force-stop -- or the guest terminated) and wake every vcpu thread that may
 * be blocked waiting for a kick or on the unpause cond, plus the reaper in
 * run_vm.  Without this, a halted/idle vcpu sleeping on vcpu_run_cond[] never
 * wakes (nothing will kick it once the kernel can no longer run the vm), so it
 * never sets vcpu_done[], the reaper never sees all threads exit, and the
 * per-VM process orphans.
 *
 * The flag is set under vm_mtx first; the per-vcpu broadcast is then issued
 * while holding vcpu_run_mtx[i], which orders against vcpu_run_loop's
 * locked check of vm_terminating before it waits -- no lost wakeup.  Finally
 * threadcond is signalled so the reaper re-evaluates vm_terminating and can
 * arm its bounded wait even when no vcpu thread will ever exit on its own.
 * Idempotent and safe to call from any vcpu thread.
 */
static void
vm_set_terminating(void)
{
	size_t i, ncpus;

	mutex_lock(&vm_mtx);
	if (vm_terminating) {
		mutex_unlock(&vm_mtx);
		return;
	}
	vm_terminating = 1;
	mutex_unlock(&vm_mtx);

	ncpus = current_vm->vm_params.vmc_ncpus;
	for (i = 0; i < ncpus; i++) {
		mutex_lock(&vcpu_run_mtx[i]);
		pthread_cond_broadcast(&vcpu_run_cond[i]);
		mutex_unlock(&vcpu_run_mtx[i]);

		mutex_lock(&vcpu_unpause_mtx[i]);
		pthread_cond_broadcast(&vcpu_unpause_cond[i]);
		mutex_unlock(&vcpu_unpause_mtx[i]);
	}

	/*
	 * Wake the reaper (run_vm) too.  It picks its bounded, self-exiting
	 * timed wait over the untimed wait based on vm_terminating, but only
	 * re-reads that flag when it wakes from threadcond.  If it is parked in
	 * the untimed wait with no vcpu thread about to exit (e.g. one wedged
	 * in the kernel or draining a stuck device subprocess), nothing else
	 * would ever signal threadcond and the VM_TERMINATE_TIMEOUT_SEC
	 * watchdog could never arm.  Signalled with no other lock held, so it
	 * cannot invert the reaper's threadmutex->vm_mtx order.
	 */
	mutex_lock(&threadmutex);
	pthread_cond_signal(&threadcond);
	mutex_unlock(&threadmutex);
}

/*
 * vcpu_run_loop
 *
 * Runs a single VCPU until vmm(4) requires help handling an exit,
 * or the VM terminates.
 *
 * Parameters:
 *  arg: vcpu_run_params for the VCPU being run by this thread
 *
 * Return values:
 *  NULL: the VCPU shutdown properly
 *  !NULL: error processing VCPU run, or the VCPU shutdown abnormally
 */
static void *
vcpu_run_loop(void *arg)
{
	struct vm_run_params *vrp = (struct vm_run_params *)arg;
	intptr_t ret = 0;
	uint32_t n = vrp->vrp_vcpu_id;
	int paused = 0, acked_vec = -1;

	/* Identify this thread for LAPIC/IOAPIC dispatch. */
	current_vcpu_id = n;

	for (;;) {
		/*
		 * Whole-VM teardown in progress: stop spinning and let this
		 * thread exit so the process can reap and die (see
		 * vm_set_terminating()).  Lock-free fast path; the
		 * authoritative check is under vcpu_run_mtx[n] before we wait,
		 * below.
		 */
		if (vm_terminating)
			break;

		ret = pthread_mutex_lock(&vcpu_run_mtx[n]);

		if (ret) {
			log_warnx("%s: can't lock vcpu run mtx (%d)",
			    __func__, (int)ret);
			return ((void *)ret);
		}

		mutex_lock(&vm_mtx);
		paused = (current_vm->vm_state & VM_STATE_PAUSED) != 0;
		mutex_unlock(&vm_mtx);

		/* If we need to pause, wait on the barrier. */
		if (paused) {
			ret = pthread_barrier_wait(&vm_pause_barrier);
			if (ret != 0 && ret != PTHREAD_BARRIER_SERIAL_THREAD) {
				log_warnx("%s: could not wait on pause barrier (%d)",
				    __func__, (int)ret);
				return ((void *)ret);
			}

			ret = pthread_mutex_lock(&vcpu_unpause_mtx[n]);
			if (ret) {
				log_warnx("%s: can't lock vcpu unpause mtx (%d)",
				    __func__, (int)ret);
				return ((void *)ret);
			}

			/* Interrupt may be firing, release run mtx. */
			mutex_unlock(&vcpu_run_mtx[n]);
			ret = pthread_cond_wait(&vcpu_unpause_cond[n],
			    &vcpu_unpause_mtx[n]);
			if (ret) {
				log_warnx(
				    "%s: can't wait on unpause cond (%d)",
				    __func__, (int)ret);
				break;
			}
			mutex_lock(&vcpu_run_mtx[n]);

			ret = pthread_mutex_unlock(&vcpu_unpause_mtx[n]);
			if (ret) {
				log_warnx("%s: can't unlock unpause mtx (%d)",
				    __func__, (int)ret);
				break;
			}
		}

		/*
		 * Re-read vcpu_hlt AND the pending-interrupt state under
		 * vcpu_run_mtx to avoid a lost wakeup.  The LAPIC 1ms timer
		 * thread can set IRR and call vcpu_unhalt()/kick in the window
		 * between the kernel HLT exit and vcpu_halt() (reached via
		 * vcpu_exit below) re-setting vcpu_hlt[n]=1, swallowing the
		 * wake.  A one-shot timer disarms when it fires, so nothing
		 * retries -- an idle AP would then sleep forever with the
		 * vector stuck in IRR (RCU stall; the BSP is immune because its
		 * i8259/PIT re-asserts IRQ0 every tick).  lapic_set_irr_locked
		 * sets IRR before lapic_kick takes vcpu_run_mtx[n], so a racing
		 * kick is visible to intr_pending() now that we hold the mtx.
		 * Only block when truly idle (halted with nothing pending).
		 */
		if (!vm_terminating && vcpu_hlt[n] &&
		    !intr_pending_nofire(current_vm, n)) {
			ret = pthread_cond_wait(&vcpu_run_cond[n],
			    &vcpu_run_mtx[n]);

			if (ret) {
				log_warnx(
				    "%s: can't wait on cond (%d)",
				    __func__, (int)ret);
				(void)pthread_mutex_unlock(
				    &vcpu_run_mtx[n]);
				break;
			}
		}

		/*
		 * Woken (possibly by vm_set_terminating()'s broadcast): if the
		 * VM is going away, exit now instead of issuing a run ioctl
		 * that would only fail.  Checked while holding vcpu_run_mtx[n],
		 * so it is ordered against the broadcast -- no lost wakeup.
		 */
		if (vm_terminating) {
			(void)pthread_mutex_unlock(&vcpu_run_mtx[n]);
			break;
		}
		/*
		 * A vector raced the halt (or arrived during the wait): clear
		 * the halt flag so we resume and inject it instead of blocking
		 * again next iteration against an already-disarmed one-shot.
		 * Use the nofire variant: we hold vcpu_run_mtx[n] here, and the
		 * normal intr_pending() can fire a due timer whose kick
		 * re-takes this very mutex (self-deadlock).
		 */
		if (vcpu_hlt[n] && intr_pending_nofire(current_vm, n))
			vcpu_hlt[n] = 0;

		ret = pthread_mutex_unlock(&vcpu_run_mtx[n]);

		if (ret) {
			log_warnx("%s: can't unlock mutex on cond (%d)",
			    __func__, (int)ret);
			break;
		}

		/* Apply deferred SIPI reset from our own thread context. */
		(void)vcpu_sipi_pending(current_vm->vm_vmmid, n);

		acked_vec = -1;
		if (vrp->vrp_irqready && intr_pending(current_vm, n)) {
			vrp->vrp_inject.vie_vector = intr_ack(current_vm, n);
			acked_vec = vrp->vrp_inject.vie_vector;
			vrp->vrp_inject.vie_type = VCPU_INJECT_INTR;
		} else {
			vrp->vrp_inject.vie_type = VCPU_INJECT_NONE;
		}

		/* Still more interrupts pending? */
		vrp->vrp_intr_pending = intr_pending(current_vm, n);

		if (ioctl(env->vmd_fd, VMM_IOC_RUN, vrp) == -1) {
			ret = errno;
			log_warn("%s: vm %d / vcpu %d run ioctl failed",
			    __func__, current_vm->vm_vmid, n);
			/*
			 * The kernel can no longer run this vm (ENOENT once the
			 * vm object is gone, or any other fatal run error): the
			 * whole VM is dying.  Wake the other vcpu threads so a
			 * halted sibling does not sleep forever and orphan the
			 * process.
			 */
			vm_set_terminating();
			break;
		}

		/*
		 * Gated ack: intr_ack() above moved the vector IRR->ISR
		 * speculatively.  The kernel reflects whether it actually
		 * injected by clearing vrp_inject.vie_type to VCPU_INJECT_NONE;
		 * if it is still VCPU_INJECT_INTR the guest was not
		 * interruptible (STI/MOV-SS shadow) and the vector was NOT
		 * delivered.  Undo the speculative ack so the vector returns to
		 * IRR and is retried, instead of being orphaned in ISR -- a
		 * stranded ISR bit pins PPR and permanently masks all
		 * lower-priority vectors (e.g. a stuck timer 0xec masking the
		 * vioblk completion 0x22 -> guest hangs in io_schedule).
		 */
		if (acked_vec >= 0 &&
		    vrp->vrp_inject.vie_type == VCPU_INJECT_INTR)
			intr_unack(current_vm, n, (uint8_t)acked_vec);

		/* If the VM is terminating, exit normally */
		if (vrp->vrp_exit_reason == VM_EXIT_TERMINATED) {
			/* Wake any halted sibling so it exits too. */
			vm_set_terminating();
			ret = (intptr_t)NULL;
			break;
		}

		if (vrp->vrp_exit_reason != VM_EXIT_NONE) {
			/*
			 * vmm(4) needs help handling an exit, handle in
			 * vcpu_exit.
			 */
			ret = vcpu_exit(vrp);
			if (ret)
				break;
		}
	}

	mutex_lock(&vm_mtx);
	vcpu_done[n] = 1;
	mutex_unlock(&vm_mtx);

	mutex_lock(&threadmutex);
	pthread_cond_signal(&threadcond);
	mutex_unlock(&threadmutex);

	return ((void *)ret);
}

int
vcpu_intr(uint32_t vmm_id, uint32_t vcpu_id, uint8_t intr)
{
	struct vm_intr_params vip;

	memset(&vip, 0, sizeof(vip));

	vip.vip_vm_id = vmm_id;
	vip.vip_vcpu_id = vcpu_id; /* XXX always 0? */
	vip.vip_intr = intr;

	if (ioctl(env->vmd_fd, VMM_IOC_INTR, &vip) == -1)
		return (errno);

	return (0);
}

/*
 * fd_hasdata
 *
 * Determines if data can be read from a file descriptor.
 *
 * Parameters:
 *  fd: the fd to check
 *
 * Return values:
 *  1 if data can be read from an fd, or 0 otherwise.
 */
int
fd_hasdata(int fd)
{
	struct pollfd pfd[1];
	int nready, hasdata = 0;

	pfd[0].fd = fd;
	pfd[0].events = POLLIN;
	nready = poll(pfd, 1, 0);
	if (nready == -1)
		log_warn("checking file descriptor for data failed");
	else if (nready == 1 && pfd[0].revents & POLLIN)
		hasdata = 1;
	return (hasdata);
}

/*
 * mutex_lock
 *
 * Wrapper function for pthread_mutex_lock that does error checking and that
 * exits on failure
 */
void
mutex_lock(pthread_mutex_t *m)
{
	int ret;

	ret = pthread_mutex_lock(m);
	if (ret) {
		errno = ret;
		fatal("could not acquire mutex");
	}
}

/*
 * mutex_unlock
 *
 * Wrapper function for pthread_mutex_unlock that does error checking and that
 * exits on failure
 */
void
mutex_unlock(pthread_mutex_t *m)
{
	int ret;

	ret = pthread_mutex_unlock(m);
	if (ret) {
		errno = ret;
		fatal("could not release mutex");
	}
}


void
vm_pipe_init(struct vm_dev_pipe *p, void (*cb)(int, short, void *))
{
	vm_pipe_init2(p, cb, NULL);
}

/*
 * vm_pipe_init2
 *
 * Initialize a vm_dev_pipe, setting up its file descriptors and its
 * event structure with the given callback and argument.
 *
 * Parameters:
 *  p: pointer to vm_dev_pipe struct to initizlize
 *  cb: callback to use for READ events on the read end of the pipe
 *  arg: pointer to pass to the callback on event trigger
 */
void
vm_pipe_init2(struct vm_dev_pipe *p, void (*cb)(int, short, void *), void *arg)
{
	int ret;
	int fds[2];

	memset(p, 0, sizeof(struct vm_dev_pipe));

	ret = pipe2(fds, O_CLOEXEC);
	if (ret)
		fatal("failed to create vm_dev_pipe pipe");

	p->read = fds[0];
	p->write = fds[1];

	event_set(&p->read_ev, p->read, EV_READ | EV_PERSIST, cb, arg);
}

/*
 * vm_pipe_send
 *
 * Send a message to an emulated device vie the provided vm_dev_pipe. This
 * relies on the fact sizeof(msg) < PIPE_BUF to ensure atomic writes.
 *
 * Parameters:
 *  p: pointer to initialized vm_dev_pipe
 *  msg: message to send in the channel
 */
void
vm_pipe_send(struct vm_dev_pipe *p, enum pipe_msg_type msg)
{
	size_t n;
	n = write(p->write, &msg, sizeof(msg));
	if (n != sizeof(msg))
		fatal("failed to write to device pipe");
}

/*
 * vm_pipe_recv
 *
 * Receive a message for an emulated device via the provided vm_dev_pipe.
 * Returns the message value, otherwise will exit on failure. This relies on
 * the fact sizeof(enum pipe_msg_type) < PIPE_BUF for atomic reads.
 *
 * Parameters:
 *  p: pointer to initialized vm_dev_pipe
 *
 * Return values:
 *  a value of enum pipe_msg_type or fatal exit on read(2) error
 */
enum pipe_msg_type
vm_pipe_recv(struct vm_dev_pipe *p)
{
	size_t n;
	enum pipe_msg_type msg;
	n = read(p->read, &msg, sizeof(msg));
	if (n != sizeof(msg))
		fatal("failed to read from device pipe");

	return msg;
}

/*
 * Re-map the guest address space using vmm(4)'s VMM_IOC_SHAREMEM
 *
 * Returns 0 on success or an errno in event of failure.
 */
int
remap_guest_mem(struct vmd_vm *vm, int vmm_fd)
{
	size_t i;
	struct vm_sharemem_params vsp;

	if (vm == NULL)
		return (EINVAL);

	/* Initialize using our original creation parameters. */
	memset(&vsp, 0, sizeof(vsp));
	vsp.vsp_nmemranges = vm->vm_params.vmc_nmemranges;
	vsp.vsp_vm_id = vm->vm_vmmid;
	memcpy(&vsp.vsp_memranges, &vm->vm_params.vmc_memranges,
	    sizeof(vsp.vsp_memranges));

	/* Ask vmm(4) to enter a shared mapping to guest memory. */
	if (ioctl(vmm_fd, VMM_IOC_SHAREMEM, &vsp) == -1)
		return (errno);

	/* Update with the location of the new mappings. */
	for (i = 0; i < vsp.vsp_nmemranges; i++)
		vm->vm_params.vmc_memranges[i].vmr_va = vsp.vsp_va[i];

	return (0);
}

void
vcpu_halt(uint32_t vcpu_id)
{
	/* vcpu_run_mtx: ordered with vcpu_run_loop's check + cond_wait. */
	mutex_lock(&vcpu_run_mtx[vcpu_id]);
	vcpu_hlt[vcpu_id] = 1;
	mutex_unlock(&vcpu_run_mtx[vcpu_id]);
}

/*
 * Signal inside vcpu_run_mtx so the wakeup cannot be lost between
 * vcpu_run_loop's halted check and its cond_wait.
 */
void
vcpu_unhalt(uint32_t vcpu_id)
{
	mutex_lock(&vcpu_run_mtx[vcpu_id]);
	vcpu_hlt[vcpu_id] = 0;
	pthread_cond_signal(&vcpu_run_cond[vcpu_id]);
	mutex_unlock(&vcpu_run_mtx[vcpu_id]);
}

void
vcpu_signal_run(uint32_t vcpu_id)
{
	int ret;

	mutex_lock(&vcpu_run_mtx[vcpu_id]);
	ret = pthread_cond_signal(&vcpu_run_cond[vcpu_id]);
	if (ret)
		fatalx("%s: can't signal (%d)", __func__, ret);
	mutex_unlock(&vcpu_run_mtx[vcpu_id]);
}
