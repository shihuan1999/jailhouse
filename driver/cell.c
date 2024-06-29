/*
 * Jailhouse, a Linux-based partitioning hypervisor
 *
 * Copyright (c) Siemens AG, 2013-2016
 *
 * Authors:
 *  Jan Kiszka <jan.kiszka@siemens.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 */

/* For compatibility with older kernel versions */
#include <linux/version.h>

#include <linux/cpu.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <asm/cacheflush.h>

#include "cell.h"
#include "main.h"
#include "pci.h"
#include "sysfs.h"

// 包含jailhouse/hypercall.h文件，这个头文件定义了与jailhouse系统相关的重要函数和数据结构
#include <jailhouse/hypercall.h>

// 如果Linux版本小于5,7,0，则定义add_cpu和remove_cpu函数
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,7,0)
#define add_cpu(cpu)		cpu_up(cpu)
#define remove_cpu(cpu)		cpu_down(cpu)
#endif

// 定义root_cell变量，指向根cell结构体
struct cell *root_cell;

// 定义一个cells列表，用于存储cell结构体
static LIST_HEAD(cells);
// 定义一个offlined_cpus变量，用于存储离线的cpu mask
static cpumask_t offlined_cpus;

// 释放cell结构体的kobject对象
void jailhouse_cell_kobj_release(struct kobject *kobj)
{
	struct cell *cell = container_of(kobj, struct cell, kobj);

	// 调用jailhouse_pci_cell_cleanup函数清理cell
	jailhouse_pci_cell_cleanup(cell);
	// 释放cell的内存区域
	vfree(cell->memory_regions);
	// 释放cell结构体
	kfree(cell);
}

// 创建cell结构体
static struct cell *cell_create(const struct jailhouse_cell_desc *cell_desc)
{
	struct cell *cell;
	unsigned int id;
	int err;

	// 如果内存区域数量超过ULONG_MAX，返回错误
	if (cell_desc->num_memory_regions >=
	    ULONG_MAX / sizeof(struct jailhouse_memory))
		return ERR_PTR(-EINVAL);

	/* determine cell id */
	id = 0;
retry:
	list_for_each_entry(cell, &cells, entry)
		if (cell->id == id) {
			id++;
			goto retry;
		}

	cell = kzalloc(sizeof(*cell), GFP_KERNEL);
	if (!cell)
		return ERR_PTR(-ENOMEM);

	INIT_LIST_HEAD(&cell->entry);

	cell->id = id;

	// 将cell的cpu掩码复制到cell中
	bitmap_copy(cpumask_bits(&cell->cpus_assigned),
		    jailhouse_cell_cpu_set(cell_desc),
		    min((unsigned int)nr_cpumask_bits,
		        cell_desc->cpu_set_size * 8));

	cell->num_memory_regions = cell_desc->num_memory_regions;
	cell->memory_regions = vmalloc(sizeof(struct jailhouse_memory) *
				       cell->num_memory_regions);
	if (!cell->memory_regions) {
		kfree(cell);
		return ERR_PTR(-ENOMEM);
	}

	// 将cell的名称复制到cell中
	memcpy(cell->name, cell_desc->name, JAILHOUSE_CELL_ID_NAMELEN);
	cell->name[JAILHOUSE_CELL_ID_NAMELEN] = 0;

	// 将cell的内存区域复制到cell中
	memcpy(cell->memory_regions, jailhouse_cell_mem_regions(cell_desc),
	       sizeof(struct jailhouse_memory) * cell->num_memory_regions);

	// 设置cell的pci
	err = jailhouse_pci_cell_setup(cell, cell_desc);
	if (err) {
		vfree(cell->memory_regions);
		kfree(cell);
		return ERR_PTR(err);
	}

	// 创建cell的sysfs
	err = jailhouse_sysfs_cell_create(cell);
	if (err)
		/* cleanup done by jailhouse_sysfs_cell_create */
		return ERR_PTR(err);

	return cell;
}

// 注册cell
static void cell_register(struct cell *cell)
{
	list_add_tail(&cell->entry, &cells);
	jailhouse_sysfs_cell_register(cell);
}

// 查找cell
static struct cell *find_cell(struct jailhouse_cell_id *cell_id)
{
	struct cell *cell;

	list_for_each_entry(cell, &cells, entry)
		// 如果cell_id->id与cell->id相等，或者cell_id->id为JAILHOUSE_CELL_ID_UNUSED并且cell->name与cell_id->name相等
		if (cell_id->id == cell->id ||
		    (cell_id->id == JAILHOUSE_CELL_ID_UNUSED &&
		     strcmp(cell->name, cell_id->name) == 0))
			return cell;
	return NULL;
}

// 删除cell
static void cell_delete(struct cell *cell)
{
	list_del(&cell->entry);
	jailhouse_sysfs_cell_delete(cell);
}

// 准备根cell
int jailhouse_cell_prepare_root(const struct jailhouse_cell_desc *cell_desc)
{
	root_cell = cell_create(cell_desc);
	if (IS_ERR(root_cell))
		return PTR_ERR(root_cell);

	return 0;
}

// 注册根cell
void jailhouse_cell_register_root(void)
{
	root_cell->id = 0;
	cell_register(root_cell);
}

// 删除根cell
void jailhouse_cell_delete_root(void)
{
	cell_delete(root_cell);
	root_cell = NULL;
}

int jailhouse_cmd_cell_create(struct jailhouse_cell_create __user *arg)
{
	// 定义cell_params结构体变量，用于存储cell创建参数
	struct jailhouse_cell_create cell_params;
	// 定义config变量，用于存储cell配置信息
	struct jailhouse_cell_desc *config;
	// 定义cell_id变量，用于存储cell的id信息
	struct jailhouse_cell_id cell_id;
	// 定义user_config变量，用于存储cell配置信息
	void __user *user_config;
	// 定义cell变量，用于存储创建的cell信息
	struct cell *cell;
	// 定义cpu变量，用于存储cpu信息
	unsigned int cpu;
	// 定义err变量，用于存储错误信息
	int err = 0;

	// 如果copy_from_user函数执行失败，返回-EFAULT
	if (copy_from_user(&cell_params, arg, sizeof(cell_params)))
		return -EFAULT;

	// 分配内存，用于存储cell配置信息
	config = kmalloc(cell_params.config_size, GFP_USER | __GFP_NOWARN);
	// 如果分配内存失败，返回-ENOMEM
	if (!config)
		return -ENOMEM;

	// 将用户空间中的cell配置信息copy到config变量中
	user_config = (void __user *)(unsigned long)cell_params.config_address;
	// 如果copy_from_user函数执行失败，返回-EFAULT，并将config释放
	if (copy_from_user(config, user_config, cell_params.config_size)) {
		err = -EFAULT;
		goto kfree_config_out;
	}

	// 如果config中的签名与JAILHOUSE_CELL_DESC_SIGNATURE不匹配，返回-EINVAL，并将config释放
	if (cell_params.config_size < sizeof(*config) ||
	    memcmp(config->signature, JAILHOUSE_CELL_DESC_SIGNATURE,
		   sizeof(config->signature)) != 0) {
		pr_err("jailhouse: Not a cell configuration\n");
		err = -EINVAL;
		goto kfree_config_out;
	}
	// 如果config中的修订号与JAILHOUSE_CONFIG_REVISION不匹配，返回-EINVAL，并将config释放
	if (config->revision != JAILHOUSE_CONFIG_REVISION) {
		pr_err("jailhouse: Configuration revision mismatch\n");
		err = -EINVAL;
		goto kfree_config_out;
	}
	// 如果config中的架构与JAILHOUSE_ARCHITECTURE不匹配，返回-EINVAL，并将config释放
	if (config->architecture != JAILHOUSE_ARCHITECTURE) {
		pr_err("jailhouse: Configuration architecture mismatch\n");
		err = -EINVAL;
		goto kfree_config_out;
	}

	// 将config中的name字段设置为空
	config->name[JAILHOUSE_CELL_NAME_MAXLEN] = 0;

	// 如果config中的virtual console active标志位为真，将config中的virtual console permitted标志位设置为真
	if (CELL_FLAGS_VIRTUAL_CONSOLE_ACTIVE(config->flags))
		config->flags |= JAILHOUSE_CELL_VIRTUAL_CONSOLE_PERMITTED;

	// 互斥锁锁定
	if (mutex_lock_interruptible(&jailhouse_lock) != 0) {
		err = -EINTR;
		goto kfree_config_out;
	}

	// 如果jailhouse未启用，返回-EINVAL
	if (!jailhouse_enabled) {
		err = -EINVAL;
		goto unlock_out;
	}

	cell_id.id = JAILHOUSE_CELL_ID_UNUSED;
	// 复制配置中的name字段到cell_id.name
	memcpy(cell_id.name, config->name, sizeof(cell_id.name));
	// 在cells中查找cell_id，如果存在，则err为-EEXIST，否则继续
	if (find_cell(&cell_id) != NULL) {
		err = -EEXIST;
		goto unlock_out;
	}

	// 创建cell
	cell = cell_create(config);
	if (IS_ERR(cell)) {
		err = PTR_ERR(cell);
		goto unlock_out;
	}

	// 将config中的id赋值给cell
	config->id = cell->id;

	// 如果cell中的cpus_assigned不是root_cell中cpus_assigned的子集，则err为-EBUSY，否则继续
	if (!cpumask_subset(&cell->cpus_assigned, &root_cell->cpus_assigned)) {
		err = -EBUSY;
		goto error_cell_delete;
	}

	/* Off-line each CPU assigned to the new cell and remove it from the
	 * root cell's set. */
	for_each_cpu(cpu, &cell->cpus_assigned) {
#ifdef CONFIG_X86
		if (cpu == 0) {
			/*
			 * On x86, Linux only parks CPU 0 when offlining it and
			 * expects to be able to get it back by sending an IPI.
			 * This is not support by Jailhouse wich destroys the
			 * CPU state across non-root assignments.
			 */
			pr_err("Cannot assign CPU 0 to other cells\n");
			err = -EINVAL;
			goto error_cpu_online;
		}
#endif
		if (cpu_online(cpu)) {
			err = remove_cpu(cpu);
			if (err)
				goto error_cpu_online;
			cpumask_set_cpu(cpu, &offlined_cpus);
		}
		cpumask_clear_cpu(cpu, &root_cell->cpus_assigned);
	}

	// 对cell中的pci设备进行处理
	jailhouse_pci_do_all_devices(cell, JAILHOUSE_PCI_TYPE_DEVICE,
	                             JAILHOUSE_PCI_ACTION_CLAIM);

	// 调用jailhouse_call_arg1，参数为config，如果返回的err小于0，则继续
	err = jailhouse_call_arg1(JAILHOUSE_HC_CELL_CREATE, __pa(config));
	if (err < 0)
		goto error_cpu_online;

	// 将cell注册到cells中
	cell_register(cell);

	// 打印创建cell的信息
	pr_info("Created Jailhouse cell \"%s\"\n", config->name);

unlock_out:
	mutex_unlock(&jailhouse_lock);

kfree_config_out:
	kfree(config);

	return err;

error_cpu_online:
	// 对cpu进行处理
	for_each_cpu(cpu, &cell->cpus_assigned) {
		if (!cpu_online(cpu) && add_cpu(cpu) == 0)
			cpumask_clear_cpu(cpu, &offlined_cpus);
		cpumask_set_cpu(cpu, &root_cell->cpus_assigned);
	}

error_cell_delete:
	// 删除cell
	cell_delete(cell);
	goto unlock_out;
}

// 静态函数：cell_management_prologue
// 功能：cell管理前缀
// 参数：cell_id：cell_id结构体指针；cell_ptr：cell结构体指针
// 返回值：0：成功；-EINTR：被中断；-EINVAL：无效；-ENOENT：未找到
static int cell_management_prologue(struct jailhouse_cell_id *cell_id,
				    struct cell **cell_ptr)
{
	// 将cell_id结构体中的name字段清零
	cell_id->name[JAILHOUSE_CELL_ID_NAMELEN] = 0;

	// 互斥锁锁定，成功返回0，被中断返回-EINTR
	if (mutex_lock_interruptible(&jailhouse_lock) != 0)
		return -EINTR;

	// 如果jailhouse未启用，解锁互斥锁，返回-EINVAL
	if (!jailhouse_enabled) {
		mutex_unlock(&jailhouse_lock);
		return -EINVAL;
	}

	// 在cell_ptr中存储找到的cell结构体
	*cell_ptr = find_cell(cell_id);
	// 未找到cell，解锁互斥锁，返回-ENOENT
	if (*cell_ptr == NULL) {
		mutex_unlock(&jailhouse_lock);
		return -ENOENT;
	}
	// 成功找到cell，返回0
	return 0;
}

// 定义内存请求标志
#define MEM_REQ_FLAGS	(JAILHOUSE_MEM_WRITE | JAILHOUSE_MEM_LOADABLE)

// 加载镜像
static int load_image(struct cell *cell,
		      struct jailhouse_preload_image __user *uimage)
{
	struct jailhouse_preload_image image;
	const struct jailhouse_memory *mem;
	unsigned int regions, page_offs;
	u64 image_offset, phys_start;
	void *image_mem;
	int err = 0;

	// 从用户空间复制镜像信息到image变量
	if (copy_from_user(&image, uimage, sizeof(image)))
		return -EFAULT;

	// 如果镜像大小为0，则直接返回
	if (image.size == 0)
		return 0;

	// 遍历cell的内存区域
	mem = cell->memory_regions;
	for (regions = cell->num_memory_regions; regions > 0; regions--) {
		image_offset = image.target_address - mem->virt_start;
		// 如果镜像的起始地址在内存区域的范围内，并且镜像大小不超过内存区域的大小，则继续
		if (image.target_address >= mem->virt_start &&
		    image_offset < mem->size) {
			// 如果镜像大小超过内存区域的大小或者内存区域的请求标志不正确，则返回错误
			if (image.size > mem->size - image_offset ||
			    (mem->flags & MEM_REQ_FLAGS) != MEM_REQ_FLAGS)
				return -EINVAL;
			break;
		}
		mem++;
	}
	// 如果遍历完内存区域都没有找到合适的内存区域，则返回错误
	if (regions == 0)
		return -EINVAL;

	// 计算物理起始地址
	phys_start = (mem->phys_start + image_offset) & PAGE_MASK;
	page_offs = offset_in_page(image_offset);
	// 进行内存映射
	image_mem = jailhouse_ioremap(phys_start, 0,
				      PAGE_ALIGN(image.size + page_offs));
	// 如果内存映射失败，则返回错误
	if (!image_mem) {
		pr_err("jailhouse: Unable to map cell RAM at %08llx "
		       "for image loading\n",
		       (unsigned long long)(mem->phys_start + image_offset));
		return -EBUSY;
	}

	// 将用户空间的内容复制到内存映射区域
	if (copy_from_user(image_mem + page_offs,
			   (void __user *)(unsigned long)image.source_address,
			   image.size))
		err = -EFAULT;
	/*
	 * ARMv7 and ARMv8 require to clean D-cache and invalidate I-cache for
	 * memory containing new instructions. On x86 this is a NOP.
	 */
	flush_icache_range((unsigned long)(image_mem + page_offs),
			   (unsigned long)(image_mem + page_offs) + image.size);
#ifdef CONFIG_ARM
	/*
	 * ARMv7 requires to flush the written code and data out of D-cache to
	 * allow the guest starting off with caches disabled.
	 */
	__cpuc_flush_dcache_area(image_mem + page_offs, image.size);
#endif

	// 取消内存映射
	vunmap(image_mem);

	return err;
}

int jailhouse_cmd_cell_load(struct jailhouse_cell_load __user *arg) //加载cell
{
	struct jailhouse_preload_image __user *image = arg->image; //获取用户空间传入的image参数
	struct jailhouse_cell_load cell_load; //定义cell_load结构体
	struct cell *cell; //定义cell指针
	unsigned int n; //定义unsigned int类型的变量n
	int err; //定义int类型的变量err

	if (copy_from_user(&cell_load, arg, sizeof(cell_load))) //如果从用户空间拷贝失败
		return -EFAULT; //返回错误码

	err = cell_management_prologue(&cell_load.cell_id, &cell); //调用cell_management_prologue函数，获取cell_id和cell指针
	if (err) //如果获取失败
		return err; //返回错误码

	err = jailhouse_call_arg1(JAILHOUSE_HC_CELL_SET_LOADABLE, cell->id); //调用jailhouse_call_arg1函数，设置cell加载状态
	if (err) //如果调用失败
		goto unlock_out; //跳转到unlock_out标签

	for (n = cell_load.num_preload_images; n > 0; n--, image++) { //循环遍历num_preload_images
		err = load_image(cell, image); //调用load_image函数，加载image
		if (err) //如果加载失败
			break; //跳出循环
	}

unlock_out:
	mutex_unlock(&jailhouse_lock); //解锁

	return err; //返回错误码
}

int jailhouse_cmd_cell_start(const char __user *arg)
{
	// 声明结构体变量cell_id，cell，err
	struct jailhouse_cell_id cell_id;
	struct cell *cell;
	int err;

	// 从用户空间拷贝cell_id到内存中
	if (copy_from_user(&cell_id, arg, sizeof(cell_id)))
		return -EFAULT;

	// 调用cell_management_prologue函数，获取cell，并判断cell是否为空
	err = cell_management_prologue(&cell_id, &cell);
	if (err)
		return err;

	// 调用jailhouse_call_arg1函数，向cell发送JAILHOUSE_HC_CELL_START命令
	err = jailhouse_call_arg1(JAILHOUSE_HC_CELL_START, cell->id);

	// 解锁互斥锁
	mutex_unlock(&jailhouse_lock);

	// 返回err
	return err;
}

// 定义一个函数，用于销毁cell
static int cell_destroy(struct cell *cell)
{
	// 定义一个无符号整数，用于存储CPU编号
	unsigned int cpu;
	// 定义一个整数，用于存储错误码
	int err;

	// 调用jailhouse_call_arg1函数，销毁cell
	err = jailhouse_call_arg1(JAILHOUSE_HC_CELL_DESTROY, cell->id);
	if (err)
		return err;

	// 遍历cell中的CPU，并将它们从离线状态恢复在线状态
	for_each_cpu(cpu, &cell->cpus_assigned) {
		if (cpumask_test_cpu(cpu, &offlined_cpus)) {
			if (add_cpu(cpu) != 0)
				pr_err("Jailhouse: failed to bring CPU %d "
				       "back online\n", cpu);
			cpumask_clear_cpu(cpu, &offlined_cpus);
		}
		cpumask_set_cpu(cpu, &root_cell->cpus_assigned);
	}

	// 释放cell中的设备
	jailhouse_pci_do_all_devices(cell, JAILHOUSE_PCI_TYPE_DEVICE,
	                             JAILHOUSE_PCI_ACTION_RELEASE);

	// 打印销毁cell的信息
	pr_info("Destroyed Jailhouse cell \"%s\"\n", cell->name);

	// 删除cell
	cell_delete(cell);

	return 0;
}

int jailhouse_cmd_cell_destroy(const char __user *arg)
{
	// 声明结构体变量
	struct jailhouse_cell_id cell_id;
	struct cell *cell;
	int err;

	// 将arg参数的值拷贝到cell_id中
	if (copy_from_user(&cell_id, arg, sizeof(cell_id)))
		return -EFAULT;

	// 调用cell_management_prologue函数，获取cell_id对应的cell
	err = cell_management_prologue(&cell_id, &cell);
	if (err)
		return err;

	// 调用cell_destroy函数，销毁cell
	err = cell_destroy(cell);

	// 解锁jailhouse_lock互斥锁
	mutex_unlock(&jailhouse_lock);

	// 返回err
	return err;
}

int jailhouse_cmd_cell_destroy_non_root(void)
{
	// 遍历cells链表
	struct cell *cell, *tmp;
	int err;

	list_for_each_entry_safe(cell, tmp, &cells, entry) {
		// 如果cell是根cell，则跳过
		if (cell == root_cell)
			continue;
		// 销毁cell
		err = cell_destroy(cell);
		if (err) {
			// 如果销毁失败，打印错误信息
			pr_err("Jailhouse: failed to destroy cell \"%s\"\n", cell->name);
			return err;
		}
	}

	return 0;
}
