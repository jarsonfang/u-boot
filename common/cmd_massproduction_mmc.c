#include <common.h>
#include <command.h>
#include <linux/types.h>
#include <linux/string.h>
#include <linux/ctype.h>
#include <stdarg.h>
#include <stdbool.h>
#include <u-boot/md5.h>

#define SYS_RESET              "reset"                            /* perform RESET of the CPU */
#define USB_RESET              "usb reset"                        /* reset (rescan) USB controller */
#define USB_PART               "usb part %x"                      /* print partition table of USB storage device */
#define MMC_DEV                "mmc dev %x %x"                    /* show or set current mmc device [partition] */
#define MMC_LIST               "mmc list"                         /* lists available devices */
#define MMC_PART               "mmc part"                         /* lists available partition on current mmc device */
#define MMC_WRITE              "mmc write %lx %lx %lx"            /* mmc write addr blk# cnt */
#define SEARCH_UPGRADE_FILES   "fatls %s %x:%x %s"                /* from "mmc" or "usb" */
#define LOAD_FILE_FROM_STORAGE "fatload %s %x:%x %lx %s %lx %lx"  /* from "mmc" or "usb" */
#define MD5SUM_VERIFY          "md5sum -v %lx %lx %s"             /* verify md5sum of memory area */

#define MBR_FILE_NAME          "mbr.bin"                          /* MBR record (partition table) */
#define UBOOT_FILE_NAME        "u-boot.imx"                       /* u-boot */
#define BOOT_FILE_NAME         "boot.vfat"                        /* include UIMAGE_FILE and FDT_FILE */
#define ROOTFS_FILE_NAME       "root.ext4"                        /* root file system */
#define CHKSUM_FILE_NAME       "md5sum.txt"                       /* MD5 checksum file */
#define MASPRO_FILE_NAME       "maspro.txt"                       /* production control file */

#define PREFIX                 "MASPRO: "                         /* Output prefix */
#define SEARCH_FILE_PATH       "/upgrade"                         /* Upgrade files directory on usb or mmc device, must use absolute path */

#define MBR_MD5_ENV            "mbr_md5"
#define UBOOT_MD5_ENV          "uboot_md5"
#define BOOT_MD5_ENV           "boot_md5"
#define ROOT_MD5_ENV           "root_md5"

#define MBR_BLK_START       (0x0)
#define UBOOT_BLK_START     (0x2)
#define BOOT_BLK_START      (0x2000)
#define ROOTFS_BLK_START    (0xa000)

#define MD5SUM_LENGTH       (32)
#define MAX_FILE_NAME_SIZE  (64)
#define MAX_CMD_BUF_SIZE    (128)

#define KB (0x400)     /* 1024 bytes */
#define MB (0x100000)  /* 1024 * 1024 bytes */
#define CHUNK_SIZE (8*MB) /* file read chunk size */
#define TIMEOUT (5)    /* 5s, time to wait before system reboot */

enum {
	MBR_FILE_NUM = 0,
	UBOOT_FILE_NUM,
	BOOT_FILE_NUM,
	ROOTFS_FILE_NUM,
	CHKSUM_FILE_NUM,
	MASPRO_FILE_NUM,
	MAX_FILE_NUM
};

#define LOAD_ADDR            CONFIG_LOADADDR
#define TOTAL_UPGRADE_FILES  (MAX_FILE_NUM - 2)

typedef enum update_stat_e {
	SUCCESS = 0,
	FAILED,
	NOT_CHANGED
} update_stat;

typedef struct maspro_file_ctrl_s {
	long file_size;
	char file_name[MAX_FILE_NAME_SIZE];
	bool registered;
	update_stat status;
	char md5sum[MD5SUM_LENGTH + 1];
} maspro_file_ctrl;

static maspro_file_ctrl maspro_files[MAX_FILE_NUM];

typedef enum {IF_USB, IF_MMC} if_type;
static if_type interface = IF_MMC;

static int current_dev = -1;
static int current_devpart = -1;

static bool has_chksum = false;
static bool upgrade_ok = true;

/* either in user mode or super mode */
static int maspro_user_mode = 0;
static int maspro_super_mode = 0;

static char cmd_buf[MAX_CMD_BUF_SIZE];

static char *default_filenames[MAX_FILE_NUM] = {
	[MBR_FILE_NUM] = MBR_FILE_NAME,
	[UBOOT_FILE_NUM] = UBOOT_FILE_NAME,
	[BOOT_FILE_NUM] = BOOT_FILE_NAME,
	[ROOTFS_FILE_NUM] = ROOTFS_FILE_NAME,
	[CHKSUM_FILE_NUM] = CHKSUM_FILE_NAME,
	[MASPRO_FILE_NUM] = MASPRO_FILE_NAME,
};

static char *env_names[MAX_FILE_NUM] = {
	[MBR_FILE_NUM] = MBR_MD5_ENV,
	[UBOOT_FILE_NUM] = UBOOT_MD5_ENV,
	[BOOT_FILE_NUM] = BOOT_MD5_ENV,
	[ROOTFS_FILE_NUM] = ROOT_MD5_ENV,
};

static int maspro_get_filenum(char *file_name) {
	if (NULL == file_name) {
		return MAX_FILE_NUM;
	}

	int i = 0;
	for (; i < MAX_FILE_NUM; i++) {
		if (strcmp(file_name, default_filenames[i]) == 0) {
			return i;
		}
	}

	return MAX_FILE_NUM;
}

static bool maspro_validate_filenum(unsigned int file_num) {
	if (file_num >= MAX_FILE_NUM) {
		printf(PREFIX "Invalid file.\n");
		return false;
	}

	return true;
}

static long maspro_get_filesize(unsigned int file_num) {
	if (!maspro_validate_filenum(file_num)) {
		return 0;
	}

	return maspro_files[file_num].file_size;
}

static void maspro_set_filesize(unsigned int file_num, long file_size) {
	if (!maspro_validate_filenum(file_num)) {
		return;
	}

	maspro_files[file_num].file_size = file_size;
}

static char *maspro_get_filename(unsigned int file_num) {
	if (!maspro_validate_filenum(file_num)) {
		return NULL;
	}
	
	if (!maspro_files[file_num].registered ) {
		return NULL;
	}

	return maspro_files[file_num].file_name;
}

static void maspro_set_filename(unsigned int file_num, char *file_name) {
	if (NULL == file_name) {
		return;
	}

	if (!maspro_validate_filenum(file_num)) {
		return;
	}

	memcpy(maspro_files[file_num].file_name, file_name, MAX_FILE_NAME_SIZE - 1);
}

static char *maspro_get_md5sum(unsigned int file_num) {
	if (!maspro_validate_filenum(file_num)) {
		return NULL;
	}

	return maspro_files[file_num].md5sum;
}

static void maspro_set_md5sum(unsigned int file_num, char *str) {
	if (NULL == str) {
		return;
	}

	if (!maspro_validate_filenum(file_num)) {
		return;
	}

	memcpy(maspro_files[file_num].md5sum, str, MD5SUM_LENGTH);
}

static int maspro_get_status(unsigned int file_num) {
	if (!maspro_validate_filenum(file_num)) {
		return -1;
	}

	return maspro_files[file_num].status;
}

static void maspro_set_status(unsigned int file_num, update_stat status) {
	if (!maspro_validate_filenum(file_num)) {
		return;
	}

	maspro_files[file_num].status = status;
}

static void maspro_set_registered(unsigned int file_num, bool registered) {
	if (!maspro_validate_filenum(file_num)) {
		return;
	}

	maspro_files[file_num].registered = registered;

	if (CHKSUM_FILE_NUM == file_num) {
		has_chksum = true;
	}
	else if (MASPRO_FILE_NUM == file_num) {
		maspro_super_mode = 1;
	}
}

static bool maspro_get_registered(unsigned int file_num) {
	if (!maspro_validate_filenum(file_num)) {
		return false;
	}

	return maspro_files[file_num].registered;
}

/*
 * register upgrade files, called by fatls command
 */
void maspro_register_file(long file_size, char *file_name) {
	if (NULL == file_name) {
		return;
	}

	int filenum = maspro_get_filenum(file_name);
	if (MAX_FILE_NUM == filenum) {
		return;
	}

	maspro_set_filename(filenum, file_name);
	maspro_set_filesize(filenum, file_size);
	maspro_set_registered(filenum, true);

	printf(PREFIX "%s registered!\n", file_name);
}

/*
 * get current device,
 * called by mmc dev & mmc list or usb start command
 */
void maspro_register_dev(int dev) {
	current_dev = dev;
}

/*
 * get current partition of current device,
 * called by mmc part or usb part command
 */
void maspro_register_devpart(int part) {
	current_devpart = part;
}

static void die_loop(void) {
	while (1) {
		mdelay(1); /* delay 1ms */
	}
}

static void sys_reboot(void) {
	run_command(SYS_RESET, 0);
}

static void enable_lcd_output(void) {
	setenv("stdout", "vga,serial");
}

static void disable_lcd_output(void) {
	setenv("stdout", "serial");
}

static int lcd_print(const char *fmt, ...) {
	int ret;
	va_list ap;

	enable_lcd_output();

	va_start(ap, fmt);
	ret = vprintf(fmt, ap);
	va_end(ap);

	disable_lcd_output();
	return ret;
}

static void save_env(void) {
	run_command("saveenv", 0);
}

/*
 * Search external storage device
 * return 0 if there has one, otherwise, return -1.
 */
static int scan_storage(void) {
	/* run command mmc dev & mmc list to search SD card (slot 1) */
	snprintf(cmd_buf, sizeof(cmd_buf), MMC_DEV, 1, 0);
	run_command(cmd_buf, 0);
	run_command(MMC_LIST, 0);

	if (1 == current_dev) {
		/* SD card found */
		run_command(MMC_PART, 0);
	}
	else {
		/* SD card not found, scan USB storage if maspro_user_mode is set */
		if (maspro_user_mode) {
			interface = IF_USB;
			run_command(USB_RESET, 0);
			if (-1 != current_dev) {
				/* USB storage found */
				snprintf(cmd_buf, sizeof(cmd_buf), USB_PART, current_dev);
				run_command(cmd_buf, 0);
			}
		}
	}

	if ((-1 == current_dev) || (-1 == current_devpart)) {
		if (IF_USB == interface) {
			lcd_print(PREFIX "storage device not found!\n");
		}
		else {
			printf(PREFIX "storage device not found!\n");
		}

		return -1;
	}

	return 0;
}

/*
 * Scan storage for upgrade files
 */
static void search_upgrade_files(const char *dir) {
	snprintf(cmd_buf, sizeof(cmd_buf), SEARCH_UPGRADE_FILES,
			  (IF_USB == interface) ? "usb" : "mmc", current_dev, current_devpart, dir);
	run_command(cmd_buf, 0);
}

/*
 * Read size bytes at pos from file specified by filename to memory addr,
 * If size is 0, the load stops on end of file. return number of bytes read.
 */
static ulong read_file(unsigned long addr, char *file_name, long size, long pos) {
	if (NULL == file_name) {
		return 0;
	}
	
	char file_path[64] = {'\0'};
	snprintf(file_path, sizeoof(file_path), "%s/%s", SEARCH_FILE_PATH, file_name);
	file_path[sizeof(file_path) - 1] = '\0';

	snprintf(cmd_buf, sizeof(cmd_buf), LOAD_FILE_FROM_STORAGE,
			  (IF_USB == interface) ? "usb" : "mmc", current_dev, current_devpart, addr, file_path, size, pos);
	run_command(cmd_buf, 0);

	return getenv_ulong("filesize", 16, 0);
}

/*
 * Convert a string to lowercase.
 */
static void downcase(char *str)
{
	while (*str != '\0') {
		*str = tolower(*str);
		str++;
	}
}

/*
 * parse a single md5sum result
 */
static void parse_md5sum_result(char *str) {
	if (NULL == str) {
		return;
	}

	size_t size;
	char *end;
	char *filename;

	str = strim(str);
	size = strlen(str);
	if (0 == size) {
		return;
	}

	end = str + size - 1;
	while (end > str && !isspace(*end)) {
		end--;
	}

	filename = end + 1;
	downcase(filename);

	int filenum = maspro_get_filenum(filename);
	if (MAX_FILE_NUM == filenum) {
		lcd_print(PREFIX "invalid checksum result !\n");
		return;
	}

	maspro_set_md5sum(filenum, str);
}

/*
 * parse md5sum results, text format as below (generated by md5sum tool):
 * 3e65060fb2a15d15b6cccb8b0e12672e  mbr.bin
 * f2aa5d6196449a88a8a94aaf6fa2556b  u-boot.imx
 */
static void md5sum_parse(void) {
	char *file_name = maspro_get_filename(CHKSUM_FILE_NUM);

	if (NULL == file_name) {
		return;
	}

	/* read file */
	long size = read_file(LOAD_ADDR, file_name, 0, 0);
	if (0 == size) {
		lcd_print(PREFIX "read checksum file failed!\n");
		return;
	}

	char *str = (char *)LOAD_ADDR;
	*(str + size) = '\0'; /* NUL-terminated */

	while (*str != '\0') {
		char *p = strchr(str, '\n');

		if (NULL == p) {
			break;
		}

		*p = '\0';
		parse_md5sum_result(str);

		/* next result */
		str = (p + 1);
	}

	/* last result */
	parse_md5sum_result(str);
}

/*
 * save md5sum to environment
 */
static void md5sum_save(unsigned int file_num, char *md5sum) {
	if (NULL == md5sum) {
		return;
	}

	setenv(env_names[file_num], md5sum);
}

/*
 * compare md5sum with environment variable
 * return true if equal, otherwise, return false.
 */
static bool md5sum_check_equaled(unsigned int file_num, char *md5sum) {
	char *md5sum_env = getenv(env_names[file_num]);

	if ((NULL == md5sum) || (NULL == md5sum_env)) {
		return false;
	}

	if (strcmp(md5sum, md5sum_env) == 0) {
		return true;
	}

	return false;
}

/*
 * verify content read from file
 * return 0 on success, or != 0 on error.
 */
static int md5sum_verify_file(unsigned long addr, unsigned long size, unsigned int file_num, char *md5sum) {
	if (NULL == md5sum) {
		return -1;
	}

	long file_size = maspro_get_filesize(file_num);

	if (size != file_size) {
		lcd_print("\n" PREFIX "Invalid memory area.\n");
		return -1;
	}

	if (strlen(md5sum) != MD5SUM_LENGTH) {
		lcd_print("\n" PREFIX "Invalid md5sum.\n");
		return -1;
	}

	int ret = 0;
	snprintf(cmd_buf, sizeof(cmd_buf), MD5SUM_VERIFY, addr, size, md5sum);
	if (0 != (ret = run_command(cmd_buf, 0))) {
		lcd_print("\n" PREFIX "md5sum verify error!\n");
	}

	return ret;
}

/* calculate file block count */
static ulong cal_blkcnt(unsigned long file_size) {
	return (file_size + 0x1ff) / 0x200;
}

static void update_mbr(void) {
	long file_size = maspro_get_filesize(MBR_FILE_NUM);
	char *file_name = maspro_get_filename(MBR_FILE_NUM);
	char *md5sum = maspro_get_md5sum(MBR_FILE_NUM);

	if ((NULL == file_name) || (NULL == md5sum)) {
		return;
	}

	lcd_print("Upgrading %s ... ", file_name);

	/* sanity check */
	if (file_size != 512) { /* MBR record size is 512 bytes */
		lcd_print("\n" PREFIX "Invalid file size of %s\n", file_name);
		maspro_set_status(MBR_FILE_NUM, FAILED);
		return;
	}

	/* read file */
	ulong size = read_file(LOAD_ADDR, file_name, 0, 0);

	/* md5sum verify */
	if (0 != md5sum_verify_file(LOAD_ADDR, size, MBR_FILE_NUM, md5sum)) {
		maspro_set_status(MBR_FILE_NUM, FAILED);
		return;
	}

	/* md5sum check */
	if (md5sum_check_equaled(MBR_FILE_NUM, md5sum)) {
		maspro_set_status(MBR_FILE_NUM, NOT_CHANGED);
		lcd_print("Done\n");
		return;
	}

	/* do upgrade */
	ulong blkcnt = 1;
	snprintf(cmd_buf, sizeof(cmd_buf), MMC_DEV, 0, 0);
	run_command(cmd_buf, 0);
	snprintf(cmd_buf, sizeof(cmd_buf), MMC_WRITE, (ulong)LOAD_ADDR, (ulong)MBR_BLK_START, blkcnt);
	run_command(cmd_buf, 0);

	md5sum_save(MBR_FILE_NUM, md5sum);
	lcd_print("Done\n");
}

static void update_uboot(void) {
	long file_size = maspro_get_filesize(UBOOT_FILE_NUM);
	char *file_name = maspro_get_filename(UBOOT_FILE_NUM);
	char *md5sum = maspro_get_md5sum(UBOOT_FILE_NUM);

	if ((NULL == file_name) || (NULL == md5sum)) {
		return;
	}

	lcd_print("Upgrading %s ... ", file_name);

	/* sanity check */
	if (file_size < 100*KB || file_size > 512*KB) {
		lcd_print("\n" PREFIX "Invalid file size of %s\n", file_name);
		maspro_set_status(UBOOT_FILE_NUM, FAILED);
		return;
	}

	/* read file */
	ulong size = read_file(LOAD_ADDR, file_name, 0, 0);

	/* md5sum verify */
	if (0 != md5sum_verify_file(LOAD_ADDR, size, UBOOT_FILE_NUM, md5sum)) {
		maspro_set_status(UBOOT_FILE_NUM, FAILED);
		return;
	}

	/* md5sum check */
	if (md5sum_check_equaled(UBOOT_FILE_NUM, md5sum)) {
		maspro_set_status(UBOOT_FILE_NUM, NOT_CHANGED);
		lcd_print("Done\n");
		return;
	}

	/* do upgrade */
	ulong blkcnt = cal_blkcnt(size);
	snprintf(cmd_buf, sizeof(cmd_buf), MMC_DEV, 0, 0);
	run_command(cmd_buf, 0);
	snprintf(cmd_buf, sizeof(cmd_buf), MMC_WRITE, (ulong)LOAD_ADDR, (ulong)UBOOT_BLK_START, blkcnt);
	run_command(cmd_buf, 0);

	/* Patch the DCD table to the right ddr size depending on CPU type */
	run_command("patch_ddr_size", 0);

	md5sum_save(UBOOT_FILE_NUM, md5sum);
	lcd_print("Done\n");
}

static void update_boot_part(void) {
	//long file_size = maspro_get_filesize(BOOT_FILE_NUM);
	char *file_name = maspro_get_filename(BOOT_FILE_NUM);
	char *md5sum = maspro_get_md5sum(BOOT_FILE_NUM);
	ulong chunk_size = CHUNK_SIZE;

	if ((NULL == file_name) || (NULL == md5sum)) {
		return;
	}

	lcd_print("Upgrading %s ... ", file_name);

#if 0
	/* sanity check */
	if (file_size != 16*MB) { /* BOOT_SPACE size is 16 MiB */
		lcd_print("\n" PREFIX "Invalid file size of %s\n", file_name);
		maspro_set_status(BOOT_FILE_NUM, FAILED);
		return;
	}

	/* read file */
	ulong size = read_file(LOAD_ADDR, file_name, 0, 0);

	/* md5sum verify */
	if (0 != md5sum_verify_file(LOAD_ADDR, size, BOOT_FILE_NUM, md5sum)) {
		maspro_set_status(BOOT_FILE_NUM, FAILED);
		return;
	}
#else

	// do MD5SUM verify by chunks.
	void *buf;
	long pos = 0;
	unsigned long bytes = 0;
	struct MD5Context mdContext;
	unsigned char md5sum_code[16] = {0};
	char md5sum_str[MD5SUM_LENGTH + 1] = {'\0'};

	buf = map_sysmem(LOAD_ADDR, chunk_size);
	MD5Init(&mdContext);
	while((bytes = read_file(LOAD_ADDR, file_name, chunk_size, pos)) != 0) {
	    pos += bytes;
	    MD5Update(&mdContext, buf, bytes);
	}
	MD5Final(md5sum_code, &mdContext);
	unmap_sysmem(buf);

	int i = 0;
    for (i = 0; i < 16; i++) {
		sprintf(md5sum_str + 2*i, "%02x", md5sum_code[i]);
	}

	if(0 != strncmp(md5sum_str, md5sum, MD5SUM_LENGTH))
	{
	    maspro_set_status(ROOTFS_FILE_NUM, FAILED);
		lcd_print("\n" PREFIX "md5sum verify error!\n");
		return;
	}
#endif

	/* md5sum check */
	if (md5sum_check_equaled(BOOT_FILE_NUM, md5sum)) {
		maspro_set_status(BOOT_FILE_NUM, NOT_CHANGED);
		lcd_print("Done\n");
		return;
	}


#if 0
	/* do upgrade */
	ulong blkcnt = cal_blkcnt(size);
	snprintf(cmd_buf, sizeof(cmd_buf), MMC_DEV, 0, 0);
	run_command(cmd_buf, 0);
	snprintf(cmd_buf, sizeof(cmd_buf), MMC_WRITE, (ulong)LOAD_ADDR, (ulong)BOOT_BLK_START, blkcnt);
	run_command(cmd_buf, 0);
#else
	/*
	 * do upgrade
	 * do it in chunks of 64M to fit into DDR RAM of the smallest module
	 */
	snprintf(cmd_buf, sizeof(cmd_buf), MMC_DEV, 0, 0);
	run_command(cmd_buf, 0);

	ulong blkcnt = 0;
	ulong blkstart = BOOT_BLK_START;
	ulong file_pos = 0;
	ulong size = 0;
	do {
		size = read_file(LOAD_ADDR, file_name, chunk_size, file_pos);
		blkcnt = cal_blkcnt(size);
		snprintf(cmd_buf, sizeof(cmd_buf), MMC_WRITE, (ulong)LOAD_ADDR, blkstart, blkcnt);
		run_command(cmd_buf, 0);

		file_pos += size;
		blkstart += blkcnt;
	} while (size == chunk_size);
#endif
	md5sum_save(BOOT_FILE_NUM, md5sum);
	lcd_print("Done\n");
}

static void update_rootfs(void) {
	char *file_name = maspro_get_filename(ROOTFS_FILE_NUM);
	char *md5sum = maspro_get_md5sum(ROOTFS_FILE_NUM);
	ulong chunk_size = CHUNK_SIZE;

	if ((NULL == file_name) || (NULL == md5sum)) {
		return;
	}

	lcd_print("Upgrading %s ... ", file_name);

#if 0
	/* sanity check */
	long file_size = maspro_get_filesize(ROOTFS_FILE_NUM);
	if (file_size < 100*MB || file_size > 400*MB) { /* DRAM size is 256 MiB */
		lcd_print("\n" PREFIX "Invalid file size of %s\n", file_name);
		maspro_set_status(BOOT_FILE_NUM, FAILED);
		return;
	}
	/* read file */
	ulong size = read_file(LOAD_ADDR, file_name, 0, 0);

	/* md5sum verify */
	if (0 != md5sum_verify_file(LOAD_ADDR, size, ROOTFS_FILE_NUM, md5sum)) {
		maspro_set_status(ROOTFS_FILE_NUM, FAILED);
		return;
	}
#else
	// do MD5SUM verify by chunks.
    void *buf;
    long pos = 0;
    unsigned long bytes = 0;
    struct MD5Context mdContext;
    unsigned char md5sum_code[16] = {0};
    char md5sum_str[MD5SUM_LENGTH + 1] = {'\0'};

    buf = map_sysmem(LOAD_ADDR, chunk_size);
    MD5Init(&mdContext);
    while((bytes = read_file(LOAD_ADDR, file_name, chunk_size, pos)) != 0) {
    	pos += bytes;
    	MD5Update(&mdContext, buf, bytes);
    }
    MD5Final(md5sum_code, &mdContext);
    unmap_sysmem(buf);

    int i = 0;
	for (i = 0; i < 16; i++) {
		sprintf(md5sum_str + 2*i, "%02x", md5sum_code[i]);
	}

	if(0 != strncmp(md5sum_str, md5sum, MD5SUM_LENGTH))
	{
		maspro_set_status(ROOTFS_FILE_NUM, FAILED);
		lcd_print("\n" PREFIX "md5sum verify error!\n");
		return;
	}
#endif

	/* md5sum check */
	if (md5sum_check_equaled(ROOTFS_FILE_NUM, md5sum)) {
		if (maspro_super_mode) {
			/* always do upgrade in super mode */
		}
		else {
			maspro_set_status(ROOTFS_FILE_NUM, NOT_CHANGED);
			lcd_print("Done\n");
			return;
		}
	}

	/*
	 * do upgrade
	 * do it in chunks of 64M to fit into DDR RAM of the smallest module
	 */
	snprintf(cmd_buf, sizeof(cmd_buf), MMC_DEV, 0, 0);
	run_command(cmd_buf, 0);

	ulong blkcnt = 0;
	ulong blkstart = ROOTFS_BLK_START;
	ulong file_pos = 0;
    ulong size = 0;
	do {
		size = read_file(LOAD_ADDR, file_name, chunk_size, file_pos);
		blkcnt = cal_blkcnt(size);
		snprintf(cmd_buf, sizeof(cmd_buf), MMC_WRITE, (ulong)LOAD_ADDR, blkstart, blkcnt);
		run_command(cmd_buf, 0);

		file_pos += size;
		blkstart += blkcnt;
	} while (size == chunk_size);

	md5sum_save(ROOTFS_FILE_NUM, md5sum);
	lcd_print("Done\n");
}

typedef void (upgrade_func_t)(void);
static upgrade_func_t *processes[] = {
		update_mbr,
		update_uboot,
		update_boot_part,
		update_rootfs,
		NULL
};

static void do_upgrade(void) {
	upgrade_func_t **func_ptr;
	for (func_ptr = processes; *func_ptr; ++func_ptr) {
		(*func_ptr)();
	}

	lcd_print("========== SUMMARY ==========\n");

	/* check status */
	int i = 0;
	for (; i < TOTAL_UPGRADE_FILES; i++) {
		bool failed = (FAILED == maspro_get_status(i));
		bool not_changed = (NOT_CHANGED == maspro_get_status(i));

		lcd_print("Upgrade %s %s [%s] %s\n", maspro_get_filename(i), "\t",
				failed ? "Failed" : "Success",
				not_changed ? "*" : "");

		if (failed) {
			upgrade_ok = false;
		}
	}
}

/*
 * Check upgrade files,
 * return true if all files get ready,
 * otherwise, return false.
 */
static bool check_files_prepared(void) {
	int i = 0;
	int count = 0;

	for (; i < TOTAL_UPGRADE_FILES; i++) {
		if(maspro_get_registered(i)) {
			count++;
		}
	}

	if (0 == count) {
		lcd_print(PREFIX "there is no upgrade file.\n");
		return false;
	}

	if (count != TOTAL_UPGRADE_FILES) {
		lcd_print("========== File Missing ==========\n");

		for (i = 0; i < TOTAL_UPGRADE_FILES; i++) {
			bool registered = maspro_get_registered(i);
			char *file_name = registered ? maspro_get_filename(i) : default_filenames[i];

			lcd_print("%s %s [%s]\n", file_name, "\t",
					registered ? "Found" : "Missing");
		}

		return false;
	}

	return true;
}

static int do_massproduction(cmd_tbl_t *cmdtp, int flag, int argc, char * const argv[]) {
#if !defined(CONFIG_MMC) && !defined(CONFIG_USB_STORAGE)
	lcd_print(PREFIX "please enable storage device by define CONFIG_MMC or CONFIG_USB_STORAGE!\n");
	return CMD_RET_USAGE;
#else
	/* clear status */
	memset(maspro_files, 0, sizeof(maspro_files));

	/* check maspro mode */
	maspro_user_mode = getenv_ulong("maspro_user_mode", 10, 0);

	/* scan storage device */
	if (-1 == scan_storage()) {
		if (0 != maspro_user_mode) {
			goto finished;
		}
		return CMD_RET_FAILURE;
	}

	/* search upgrade files */
	search_upgrade_files(SEARCH_FILE_PATH);

	if (0 == maspro_user_mode
			&& 0 == maspro_super_mode) {
		printf(PREFIX "nothing need to do.\n");
		return CMD_RET_SUCCESS;
	}

	lcd_print(PREFIX "%s\n", (!maspro_super_mode) ? "User mode" : "Super mode");
	lcd_print("========== INFO ==========\n");

	/* check checksum file */
	if (!has_chksum) {
		lcd_print(PREFIX CHKSUM_FILE_NAME " not found !\n");
		goto finished;
	}

	/* check upgrade files */
	if (!check_files_prepared()) {
		goto finished;
	}

	/* do upgrade */
	md5sum_parse();
	do_upgrade();

finished:
	/* hang if failed */
	if (!upgrade_ok) {
		lcd_print("========== ERROR ==========\n"
				"File corrupted, check your files and upgrade again ...\n");
		die_loop();
	}

	/*
	 * restore maspro_user_mode to 0,
	 * so that we will not upgrade the system again when reboot.
	 */
	setenv_ulong("maspro_user_mode", 0);

	/* save environment variables */
	save_env();

	if (!maspro_super_mode) { /* user mode */
		lcd_print("========== Done ==========\n"
				"Reboot in %d seconds ...\n", TIMEOUT);
		mdelay(TIMEOUT * 1000);
		sys_reboot();
	}
	else { /* super mode */
		lcd_print("========== Done ==========\n"
				"Please power off the system and take out of the removable storage ...\n");
		die_loop();
	}

	return CMD_RET_SUCCESS; /* can not reach here */
#endif
}

U_BOOT_CMD(
	maspro, 1, 0, do_massproduction,
	"mass production",
	"use MMC or USB device to do mass production or upgrade"
);
