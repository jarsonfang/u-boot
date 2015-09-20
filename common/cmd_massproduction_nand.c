#include <common.h>
#include <command.h>
#include <linux/types.h>
#include <linux/string.h>
#include <linux/ctype.h>
#include <stdarg.h>

#ifdef CONFIG_CMD_MASSPRODUCTION

#define USE_UBI 0 /* 0: for rootfs image made by ubinize. 1: for rootfs image made by mkfs.ubifs */

#define PRO_FILE_LOAD_ADDR  0x20000000 /* file loaded address in RAM, 0x20000000 -- CONFIG_SYS_LOAD_ADDR */
#define NAND_SECTOR_SIZE (1 << 17)     /* 128KiB fixme: get this size by nand info command */
#define NAND_SECTOR_SIZE_SHIFT (17)    /* Nand sector size shift bits */
#define NAND_PMECC_PARAMETER_COUNT 52  /* Count of NAND and PMECC parameters */
#define TIMEOUT    5                   /* 5s, time to wait before system reboot */
#define RETRY_CNT  3                   /* retry count when nand write verified failed */
#define PREFIX "MASPRO: "              /* Output prefix */

#define KB 0x400     /* 1024 bytes */
#define MB 0x100000  /* 1024 * 1024 bytes */

#define RESTART_BIOS           "reset"
#define USB_START              "usb start"
#define USB_PART               "usb part %d" // usb part [dev]
#define MMC_PART               "mmc part"    // lists available partition on current mmc device
#define SEARCH_UPGRADE_FILES   "fatls %s %d:%d" // from "mmc" or "usb"
#define LOAD_FILE_FROM_STORAGE "fatload %s %d:%d %lx %s" // from "mmc" or "usb"
#define MD5SUM_COMPUTE         "md5sum %lx %lx %s"
#define MD5SUM_VERIFY          "md5sum -v %lx %lx %s"

#define MTDPARTS_DEFAULT "mtdparts default" /* reset partition table to defaults, as below */

#define ERASE_FLASH_FOR_BOOTSTRAP "nand erase.part bootstrap" /* 128k(bootstrap) */
#define ERASE_FLASH_FOR_UBOOT     "nand erase.part uboot"     /* 512k(uboot) */
#define ERASE_FLASH_FOR_LOGO      "nand erase.part logo"      /* 128k(logo) */
#define ERASE_FLASH_FOR_DTB       "nand erase.part dtb"       /* 128k(dtb) */
#define ERASE_FLASH_FOR_UIMAGE    "nand erase.part kernel"    /* 3M(kernel) */
#define ERASE_FLASH_FOR_ROOTFS    "nand erase.part rootfs"    /* -(rootfs) */

#define NAND_READ_BOOTSTRAP       "nand read %lx bootstrap %lx"
#define NAND_READ_UBOOT           "nand read %lx uboot %lx"
#define NAND_READ_LOGO            "nand read %lx logo %lx"
#define NAND_READ_DTB             "nand read %lx dtb %lx"
#define NAND_READ_UIMAGE          "nand read %lx kernel %lx"
#define NAND_READ_ROOTFS          "nand read %lx rootfs %lx"

#define NAND_WRITE_BOOTSTRAP      "nand write.trimffs %lx bootstrap %lx"
#define NAND_WRITE_UBOOT          "nand write.trimffs %lx uboot %lx"
#define NAND_WRITE_LOGO           "nand write.trimffs %lx logo %lx"
#define NAND_WRITE_DTB            "nand write.trimffs %lx dtb %lx"
#define NAND_WRITE_UIMAGE         "nand write.trimffs %lx kernel %lx"
#define NAND_WRITE_ROOTFS         "nand write.trimffs %lx rootfs %lx"

#define UBI_PART_FOR_ROOTFS       "ubi part rootfs"
#define UBI_CREATE_VOL_ROOT       "ubi create rootfs"
#define UBI_WRITE_ROOTFS          "ubi write %lx rootfs %lx"

#define UBOOT_MD5_ENV             "uboot_md5"
#define LOGO_MD5_ENV              "logo_md5"
#define DTB_MD5_ENV               "dtb_md5"
#define UIMAGE_MD5_ENV            "uimage_md5"
#define ROOTFS_MD5_ENV            "rootfs_md5"
#define BOOTSTRAP_MD5_ENV         "bootstrap_md5"
#define BOOTSTRAP_RAM_MD5_ENV     "bootstrap_ram_md5"

#define BOOTSTRAP_FILE "bootstrap.bin"
#define UBOOT_FILE     "u-boot.bin"
#define LOGO_FILE      "logo.bmp"

#ifndef DTB_FILE
#error "you have to to define DTB_FILE in board config file!"
#endif

#define UIMAGE_FILE    "uimage"
#define ROOTFS_FILE    "rootfs.ubifs"
#define CHKSUM_FILE    "md5sum.txt"
#define MASPRO_FILE    "maspro.txt" /* Production control file, super mode. */

#define MD5SUM_LENGTH       32
#define MAX_CMD_BUF_SIZE    128
#define MAX_FILE_NAME_SIZE  64
#define TOTAL_UPGRADE_FILES 6

#define TOLOWER(c)                   \
		if((c) >= 'A' && (c) <= 'Z') \
		{                            \
			(c) += ('a' - 'A');      \
		}

enum {
	BOOTSTRAP_FILE_NUM = 0,
	UBOOT_FILE_NUM,
	LOGO_FILE_NUM,
	DTB_FILE_NUM,
	UIMAGE_FILE_NUM,
	ROOTFS_FILE_NUM,
	CHKSUM_FILE_NUM,
	MASPRO_FILE_NUM,
	MAX_FILE_NUM
};

typedef enum {false, true} bool;
typedef enum {IF_USB, IF_MMC} if_type;

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

static int current_dev = -1;
static int current_devpart = -1;
static if_type interface = IF_USB;

static bool has_chksum = false;
static bool upgrade_ok = true;

/* either in user mode or super mode */
static int maspro_user_mode = 0;
static int maspro_super_mode = 0;

static char cmd_buf[MAX_CMD_BUF_SIZE];

static char *default_filenames[MAX_FILE_NUM] = {
	[BOOTSTRAP_FILE_NUM] = BOOTSTRAP_FILE,
	[UBOOT_FILE_NUM] = UBOOT_FILE,
	[LOGO_FILE_NUM] = LOGO_FILE,
	[DTB_FILE_NUM] = DTB_FILE,
	[UIMAGE_FILE_NUM] = UIMAGE_FILE,
	[ROOTFS_FILE_NUM] = ROOTFS_FILE,
	[CHKSUM_FILE_NUM] = CHKSUM_FILE,
	[MASPRO_FILE_NUM] = MASPRO_FILE,
};

static char *env_names[MAX_FILE_NUM] = {
	[BOOTSTRAP_FILE_NUM] = BOOTSTRAP_MD5_ENV,
	[UBOOT_FILE_NUM] = UBOOT_MD5_ENV,
	[LOGO_FILE_NUM] = LOGO_MD5_ENV,
	[DTB_FILE_NUM] = DTB_MD5_ENV,
	[UIMAGE_FILE_NUM] = UIMAGE_MD5_ENV,
	[ROOTFS_FILE_NUM] = ROOTFS_MD5_ENV,
};

static char *nand_erase_cmds[MAX_FILE_NUM] = {
	[BOOTSTRAP_FILE_NUM] = ERASE_FLASH_FOR_BOOTSTRAP,
	[UBOOT_FILE_NUM] = ERASE_FLASH_FOR_UBOOT,
	[LOGO_FILE_NUM] = ERASE_FLASH_FOR_LOGO,
	[DTB_FILE_NUM] = ERASE_FLASH_FOR_DTB,
	[UIMAGE_FILE_NUM] = ERASE_FLASH_FOR_UIMAGE,
	[ROOTFS_FILE_NUM] = ERASE_FLASH_FOR_ROOTFS,
};

static char *nand_read_cmds[MAX_FILE_NUM] = {
	[BOOTSTRAP_FILE_NUM] = NAND_READ_BOOTSTRAP,
	[UBOOT_FILE_NUM] = NAND_READ_UBOOT,
	[LOGO_FILE_NUM] = NAND_READ_LOGO,
	[DTB_FILE_NUM] = NAND_READ_DTB,
	[UIMAGE_FILE_NUM] = NAND_READ_UIMAGE,
	[ROOTFS_FILE_NUM] = NAND_READ_ROOTFS,
};

static char *nand_write_cmds[MAX_FILE_NUM] = {
	[BOOTSTRAP_FILE_NUM] = NAND_WRITE_BOOTSTRAP,
	[UBOOT_FILE_NUM] = NAND_WRITE_UBOOT,
	[LOGO_FILE_NUM] = NAND_WRITE_LOGO,
	[DTB_FILE_NUM] = NAND_WRITE_DTB,
	[UIMAGE_FILE_NUM] = NAND_WRITE_UIMAGE,
	[ROOTFS_FILE_NUM] = NAND_WRITE_ROOTFS,
};

/*
 * Check whether the file_num is valid
 */
static bool validate_filenum(unsigned int file_num) {
	if (file_num > MAX_FILE_NUM) {
		printf(PREFIX "Invalid file.\n");
		return false;
	}

	return true;
}

static long maspro_get_filesize(unsigned int file_num) {
	if (!validate_filenum(file_num)) {
		return 0;
	}

	return maspro_files[file_num].file_size;
}

static void maspro_set_filesize(unsigned int file_num, long filesize) {
	if (!validate_filenum(file_num)) {
		return;
	}

	maspro_files[file_num].file_size = filesize;
}

static char *maspro_get_filename(unsigned int file_num) {
	if (!validate_filenum(file_num)) {
		return NULL;
	}

	return maspro_files[file_num].file_name;
}

static void maspro_set_filename(unsigned int file_num, char *filename) {
	if (!validate_filenum(file_num)) {
		return;
	}

	strncpy(maspro_files[file_num].file_name, filename, MAX_FILE_NAME_SIZE - 1);
}

static char *maspro_get_md5sum(unsigned int file_num) {
	if (!validate_filenum(file_num)) {
		return NULL;
	}

	return maspro_files[file_num].md5sum;
}

static void maspro_set_md5sum(unsigned int file_num, char *str) {
	if (!validate_filenum(file_num)) {
		return;
	}

	strncpy(maspro_files[file_num].md5sum, str, MD5SUM_LENGTH);
}

static int maspro_get_status(unsigned int file_num) {
	if (!validate_filenum(file_num)) {
		return -1;
	}

	return maspro_files[file_num].status;
}

static void maspro_set_status(unsigned int file_num, update_stat status) {
	if (!validate_filenum(file_num)) {
		return;
	}

	maspro_files[file_num].status = status;
}

static bool maspro_isregistered(unsigned int file_num) {
	if (!validate_filenum(file_num)) {
		return false;
	}

	return maspro_files[file_num].registered;
}

/*
 * search upgrade files, called by fatls command
 */
void maspro_register_file(long file_size, char *file_name) {
	if (NULL == file_name) {
		return;
	}

	if (0 == strcmp(file_name, BOOTSTRAP_FILE)) {
		maspro_set_filename(BOOTSTRAP_FILE_NUM, file_name);
		maspro_set_filesize(BOOTSTRAP_FILE_NUM, file_size);
		maspro_files[BOOTSTRAP_FILE_NUM].registered = true;
	}
	else if (0 == strcmp(file_name, UBOOT_FILE)) {
		maspro_set_filename(UBOOT_FILE_NUM, file_name);
		maspro_set_filesize(UBOOT_FILE_NUM, file_size);
		maspro_files[UBOOT_FILE_NUM].registered = true;
	}
	else if (0 == strcmp(file_name, LOGO_FILE)) {
		maspro_set_filename(LOGO_FILE_NUM, file_name);
		maspro_set_filesize(LOGO_FILE_NUM, file_size);
		maspro_files[LOGO_FILE_NUM].registered = true;
	}
	else if (0 == strcmp(file_name, DTB_FILE)) {
		maspro_set_filename(DTB_FILE_NUM, file_name);
		maspro_set_filesize(DTB_FILE_NUM, file_size);
		maspro_files[DTB_FILE_NUM].registered = true;
	}
	else if (0 == strcmp(file_name, UIMAGE_FILE)) {
		maspro_set_filename(UIMAGE_FILE_NUM, file_name);
		maspro_set_filesize(UIMAGE_FILE_NUM, file_size);
		maspro_files[UIMAGE_FILE_NUM].registered = true;
	}
	else if (0 == strcmp(file_name, ROOTFS_FILE)) {
		maspro_set_filename(ROOTFS_FILE_NUM, file_name);
		maspro_set_filesize(ROOTFS_FILE_NUM, file_size);
		maspro_files[ROOTFS_FILE_NUM].registered = true;
	}
	else if (0 == strcmp(file_name, CHKSUM_FILE)) {
		maspro_set_filename(CHKSUM_FILE_NUM, file_name);
		maspro_set_filesize(CHKSUM_FILE_NUM, file_size);
		has_chksum = true;
	}
	else if (0 == strcmp(file_name, MASPRO_FILE)) {
		maspro_set_filename(MASPRO_FILE_NUM, file_name);
		maspro_set_filesize(MASPRO_FILE_NUM, file_size);
		maspro_super_mode = 1;
	}
	else {
		/* Ignore */
	}
}

/*
 * get current device,
 * called by mmc part or usb start command
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
	run_command(RESTART_BIOS, 0);
}

static void enable_lcd_output(void) {
	setenv("stdout", "lcd");
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

static void clear_screen(void) {
	run_command("cls", 0);
}

static void save_env(void) {
	run_command("saveenv", 0);
}

/*
 * Search external storage device
 * return 0 if there has one, otherwise, return -1.
 */
static int search_storage(void) {
	run_command(USB_START, 0);
	if(-1 == current_dev) {
		run_command(MMC_PART, 0);
		interface = IF_MMC;
	}
	else {
		snprintf(cmd_buf, sizeof(cmd_buf), USB_PART, current_dev);
		run_command(cmd_buf, 0);
	}

	if (-1 == current_dev
			|| -1 == current_devpart) {
		printf(PREFIX "storage device not found!\n");
		return -1;
	}

	return 0;
}

/*
 * Scan storage for upgrade files
 */
static void scan_storage(void) {
	snprintf(cmd_buf, sizeof(cmd_buf), SEARCH_UPGRADE_FILES,
			  (IF_USB == interface) ? "usb" : "mmc", current_dev, current_devpart);
	run_command(cmd_buf, 0);
}

/*
 * Read file specified by filename from external storage
 * to memory offset addr, return the size of bytes read.
 */
static long read_file(long addr, char *file_name, long file_size) {
	snprintf(cmd_buf, sizeof(cmd_buf), LOAD_FILE_FROM_STORAGE,
			  (IF_USB == interface) ? "usb" : "mmc", current_dev, current_devpart, addr, file_name);
	run_command(cmd_buf, 0);

	return getenv_ulong("filesize", 16, file_size);
}

static void nand_erase(unsigned int file_num) {
	if (!validate_filenum(file_num)) {
		return;
	}

	run_command(nand_erase_cmds[file_num], 0);
}

static void nand_write(unsigned int file_num, unsigned long addr, long size) {
	if (!validate_filenum(file_num)) {
		return;
	}

	snprintf(cmd_buf, sizeof(cmd_buf), nand_write_cmds[file_num], addr, size);
	run_command(cmd_buf, 0);
}

static void nand_read(unsigned int file_num, unsigned long addr, long size) {
	if (!validate_filenum(file_num)) {
		return;
	}

	snprintf(cmd_buf, sizeof(cmd_buf), nand_read_cmds[file_num], addr, size);
	run_command(cmd_buf, 0);
}

/*
 * Convert a string to lowercase.
 */
static void downcase(char *str)
{
	while (*str != '\0') {
		TOLOWER(*str);
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
	if (!size) {
		return;
	}

	end = str + size - 1;
	while (end > str && !isspace(*end)) {
		end--;
	}

	filename = end + 1;
	downcase(filename);

	if (0 == strcmp(filename, BOOTSTRAP_FILE)) {
		maspro_set_md5sum(BOOTSTRAP_FILE_NUM, str);
	}
	else if (0 == strcmp(filename, UBOOT_FILE)) {
		maspro_set_md5sum(UBOOT_FILE_NUM, str);
	}
	else if (0 == strcmp(filename, LOGO_FILE)) {
		maspro_set_md5sum(LOGO_FILE_NUM, str);
	}
	else if (0 == strcmp(filename, DTB_FILE)) {
		maspro_set_md5sum(DTB_FILE_NUM, str);
	}
	else if (0 == strcmp(filename, UIMAGE_FILE)) {
		maspro_set_md5sum(UIMAGE_FILE_NUM, str);
	}
	else if (0 == strcmp(filename, ROOTFS_FILE)) {
		maspro_set_md5sum(ROOTFS_FILE_NUM, str);
	}
	else {
		/* Ignore */
	}
}

/*
 * parse md5sum results,
 * result text format as below, generated by md5sum tool:
 * 3e65060fb2a15d15b6cccb8b0e12672e  u-boot.bin
 * f2aa5d6196449a88a8a94aaf6fa2556b  bootstrap.bin
 */
static void md5sum_parse(void) {
	long file_size = maspro_get_filesize(CHKSUM_FILE_NUM);
	char *file_name = maspro_get_filename(CHKSUM_FILE_NUM);

	/* read file */
	long size = read_file(PRO_FILE_LOAD_ADDR, file_name, file_size);

	char *str = (char *)PRO_FILE_LOAD_ADDR;
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
 * compare md5sum with environment variable
 * return 0 if equal.
 */
static int md5sum_check(unsigned int file_num) {
	if (!validate_filenum(file_num)) {
		return -1;
	}

	char *md5sum = maspro_get_md5sum(file_num);
	char *md5sum_env = getenv(env_names[file_num]);

	if (NULL != md5sum && NULL != md5sum_env) {
		return strcmp(md5sum, md5sum_env);
	}

	return 1;
}

/*
 * save md5sum to environment
 */
static void md5sum_save(unsigned int file_num) {
	if (!validate_filenum(file_num)) {
		return;
	}

	char *md5sum = maspro_get_md5sum(file_num);
	setenv(env_names[file_num], md5sum);
}

/*
 * md5sum compute
 */
static void md5sum_compute(unsigned long addr, long size, char *env_name) {
	snprintf(cmd_buf, sizeof(cmd_buf), MD5SUM_COMPUTE, addr, size, env_name);
	run_command(cmd_buf, 0);
}

/*
 * verify content read from file
 */
static int md5sum_verify(unsigned long addr, unsigned long size, unsigned int file_num) {
	if (!has_chksum) {
		return 0;
	}

	if (!validate_filenum(file_num)) {
		return -1;
	}

	long file_size = maspro_get_filesize(file_num);
	char *file_name = maspro_get_filename(file_num);
	char *md5sum = maspro_get_md5sum(file_num);

	if (size != file_size) {
		printf(PREFIX "Invalid memory area.\n");
		return -1;
	}

	if (strlen(md5sum) != MD5SUM_LENGTH) {
		lcd_print("\n" PREFIX "Invalid md5sum.\n");
		return -1;
	}

	int ret = 0;
	snprintf(cmd_buf, sizeof(cmd_buf), MD5SUM_VERIFY, addr, size, md5sum);
	if (0 != (ret = run_command(cmd_buf, 0))) {
		lcd_print("\n" PREFIX "Invalid %s, md5sum verify error!\n", file_name);
	}

	return ret;
}

/*
 * verify content read from nand
 */
static int md5sum_veriry_nand(unsigned long addr, unsigned long size, char *md5sum) {
	snprintf(cmd_buf, sizeof(cmd_buf), MD5SUM_VERIFY, addr, size, md5sum);
	return run_command(cmd_buf, 0);
}

/*
 * Padding file to nand erase block with 0xFF
 * return size in bytes aligned to nand sector
 */
static unsigned long pad_file(long file_size) {
	int nand_sector_size = NAND_SECTOR_SIZE;
	unsigned char *p = (unsigned char *)(PRO_FILE_LOAD_ADDR + file_size);

	int i = 0;
	for(; i < nand_sector_size; i++) {
		p[i] = 0xFF;
	}

	/* NAND_SECTOR_SIZE * ((file_size / NAND_SECTOR_SIZE) + 1) */
	unsigned long size = ((file_size >> NAND_SECTOR_SIZE_SHIFT) + 1) << NAND_SECTOR_SIZE_SHIFT;

	return size;
}

static void update_bootstrap(void) {
	if (!maspro_isregistered(BOOTSTRAP_FILE_NUM)) {
		return;
	}

	long file_size = maspro_get_filesize(BOOTSTRAP_FILE_NUM);
	char *file_name = maspro_get_filename(BOOTSTRAP_FILE_NUM);

	lcd_print("Upgrading %s ... ", file_name);

	/* sanity check */
	if (file_size > 24*KB) {
		lcd_print("\n" PREFIX "Invalid %s, too big.\n", file_name);
		maspro_set_status(BOOTSTRAP_FILE_NUM, FAILED);
		return;
	}

	int count = RETRY_CNT;
	long size, total_size, write_size;

	uint32_t *nand_header         = (uint32_t *) PRO_FILE_LOAD_ADDR;
	uint32_t nand_header_size     = sizeof(uint32_t) * NAND_PMECC_PARAMETER_COUNT;
	uint32_t bootstrap_load_addr  = PRO_FILE_LOAD_ADDR + nand_header_size;
	uint32_t nand_pmecc_parameter = 0xc0c00405;

retry:

	/* read file */
	size = read_file(bootstrap_load_addr, file_name, file_size);

	/* md5sum verify */
	if (0 != md5sum_verify(bootstrap_load_addr, size, BOOTSTRAP_FILE_NUM)) {
		maspro_set_status(BOOTSTRAP_FILE_NUM, FAILED);
		return;
	}

	/* md5sum check */
	if (0 == md5sum_check(BOOTSTRAP_FILE_NUM)) {
		maspro_set_status(BOOTSTRAP_FILE_NUM, NOT_CHANGED);
		lcd_print("Done\n");
		return;
	}

	/* erase nand flash */
	nand_erase(BOOTSTRAP_FILE_NUM);

	/* initialize nand header */
	int i = 0;
	for (; i < NAND_PMECC_PARAMETER_COUNT; i++) {
		nand_header[i] = nand_pmecc_parameter;
	}

	/* fix exception vector 6th */
	uint32_t *image_size = (uint32_t *)(bootstrap_load_addr + 0x14);
	*image_size = size;

	/* pad file to nand erase block */
	total_size = size + nand_header_size;
	write_size = pad_file(total_size);

	/* write file to nand partition */
	nand_write(BOOTSTRAP_FILE_NUM, PRO_FILE_LOAD_ADDR, write_size);

	/*
	 * Verify NAND Content
	 */

	/* md5sum compute */
	md5sum_compute(PRO_FILE_LOAD_ADDR, total_size, BOOTSTRAP_RAM_MD5_ENV);

	/* read back nand content */
	nand_read(BOOTSTRAP_FILE_NUM, PRO_FILE_LOAD_ADDR, total_size);

	/* md5sum verify */
	if (0 != md5sum_veriry_nand(PRO_FILE_LOAD_ADDR, total_size, getenv(BOOTSTRAP_RAM_MD5_ENV))) {
		if (count--) {
			goto retry;
		}
		else {
			maspro_set_status(BOOTSTRAP_FILE_NUM, FAILED);
		}
	}
	else {
		md5sum_save(BOOTSTRAP_FILE_NUM);
	}

	lcd_print("Done\n");
}

static void update_uboot(void) {
	if (!maspro_isregistered(UBOOT_FILE_NUM)) {
		return;
	}

	long file_size = maspro_get_filesize(UBOOT_FILE_NUM);
	char *file_name = maspro_get_filename(UBOOT_FILE_NUM);
	char *md5sum = maspro_get_md5sum(UBOOT_FILE_NUM);

	lcd_print("Upgrading %s ... ", file_name);

	/* sanity check */
	if (file_size > 512*KB) {
		lcd_print("\n" PREFIX "Invalid %s, too big.\n", file_name);
		maspro_set_status(UBOOT_FILE_NUM, FAILED);
		return;
	}

	int count = RETRY_CNT;
	long size, write_size;

retry:

	/* read file */
	size = read_file(PRO_FILE_LOAD_ADDR, file_name, file_size);

	/* md5sum verify */
	if (0 != md5sum_verify(PRO_FILE_LOAD_ADDR, size, UBOOT_FILE_NUM)) {
		maspro_set_status(UBOOT_FILE_NUM, FAILED);
		return;
	}

	/* md5sum check */
	if (0 == md5sum_check(UBOOT_FILE_NUM)) {
		maspro_set_status(UBOOT_FILE_NUM, NOT_CHANGED);
		lcd_print("Done\n");
		return;
	}

	/* erase nand flash */
	nand_erase(UBOOT_FILE_NUM);

	/* pad file to nand erase block */
	write_size = pad_file(size);

	/* write file to nand partition */
	nand_write(UBOOT_FILE_NUM, PRO_FILE_LOAD_ADDR, write_size);

	/*
	 * Verify NAND Content
	 */

	/* read back nand content */
	nand_read(UBOOT_FILE_NUM, PRO_FILE_LOAD_ADDR, size);

	/* md5sum verify */
	if (0 != md5sum_veriry_nand(PRO_FILE_LOAD_ADDR, size, md5sum)) {
		if (count--) {
			goto retry;
		}
		else {
			maspro_set_status(UBOOT_FILE_NUM, FAILED);
		}
	}
	else {
		md5sum_save(UBOOT_FILE_NUM);
	}

	lcd_print("Done\n");
}

static void update_logo(void) {
	if (!maspro_isregistered(LOGO_FILE_NUM)) {
		return;
	}

	long file_size = maspro_get_filesize(LOGO_FILE_NUM);
	char *file_name = maspro_get_filename(LOGO_FILE_NUM);
	char *md5sum = maspro_get_md5sum(LOGO_FILE_NUM);

	lcd_print("Upgrading %s ... ", file_name);

	/* sanity check */
	if (file_size > 128*KB) {
		lcd_print("\n" PREFIX "Invalid %s, too big.\n", file_name);
		maspro_set_status(LOGO_FILE_NUM, FAILED);
		return;
	}

	int count = RETRY_CNT;
	long size, write_size;

retry:

	/* read file */
	size = read_file(PRO_FILE_LOAD_ADDR, file_name, file_size);

	/* md5sum verify */
	if (0 != md5sum_verify(PRO_FILE_LOAD_ADDR, size, LOGO_FILE_NUM)) {
		maspro_set_status(LOGO_FILE_NUM, FAILED);
		return;
	}

	/* md5sum check */
	if (0 == md5sum_check(LOGO_FILE_NUM)) {
		maspro_set_status(LOGO_FILE_NUM, NOT_CHANGED);
		lcd_print("Done\n");
		return;
	}

	/* erase nand flash */
	nand_erase(LOGO_FILE_NUM);

	/* pad file to nand erase block */
	write_size = pad_file(size);

	/* write file to nand partition */
	nand_write(LOGO_FILE_NUM, PRO_FILE_LOAD_ADDR, write_size);

	/*
	 * Verify NAND Content
	 */

	/* read back nand content */
	nand_read(LOGO_FILE_NUM, PRO_FILE_LOAD_ADDR, size);

	/* md5sum verify */
	if (0 != md5sum_veriry_nand(PRO_FILE_LOAD_ADDR, size, md5sum)) {
		if (count--) {
			goto retry;
		}
		else {
			maspro_set_status(LOGO_FILE_NUM, FAILED);
		}
	}
	else {
		md5sum_save(LOGO_FILE_NUM);
	}

	lcd_print("Done\n");
}

static void update_dtb(void) {
	if (!maspro_isregistered(DTB_FILE_NUM)) {
		return;
	}

	long file_size = maspro_get_filesize(DTB_FILE_NUM);
	char *file_name = maspro_get_filename(DTB_FILE_NUM);
	char *md5sum = maspro_get_md5sum(DTB_FILE_NUM);

	lcd_print("Upgrading %s ... ", file_name);

	/* sanity check */
	if (file_size > 128*KB) {
		lcd_print("\n" PREFIX "Invalid %s, too big.\n", file_name);
		maspro_set_status(DTB_FILE_NUM, FAILED);
		return;
	}

	int count = RETRY_CNT;
	long size, write_size;

retry:

	/* read file */
	size = read_file(PRO_FILE_LOAD_ADDR, file_name, file_size);

	/* md5sum verify */
	if (0 != md5sum_verify(PRO_FILE_LOAD_ADDR, size, DTB_FILE_NUM)) {
		maspro_set_status(DTB_FILE_NUM, FAILED);
		return;
	}

	/* md5sum check */
	if (0 == md5sum_check(DTB_FILE_NUM)) {
		maspro_set_status(DTB_FILE_NUM, NOT_CHANGED);
		lcd_print("Done\n");
		return;
	}

	/* erase nand flash */
	nand_erase(DTB_FILE_NUM);

	/* pad file to nand erase block */
	write_size = pad_file(size);

	/* write file to nand partition */
	nand_write(DTB_FILE_NUM, PRO_FILE_LOAD_ADDR, write_size);

	/*
	 * Verify NAND Content
	 */

	/* read back nand content */
	nand_read(DTB_FILE_NUM, PRO_FILE_LOAD_ADDR, size);

	/* md5sum verify */
	if (0 != md5sum_veriry_nand(PRO_FILE_LOAD_ADDR, size, md5sum)) {
		if (count--) {
			goto retry;
		}
		else {
			maspro_set_status(DTB_FILE_NUM, FAILED);
		}
	}
	else {
		md5sum_save(DTB_FILE_NUM);
	}

	lcd_print("Done\n");
}

static void update_uimage(void) {
	if (!maspro_isregistered(UIMAGE_FILE_NUM)) {
		return;
	}

	long file_size = maspro_get_filesize(UIMAGE_FILE_NUM);
	char *file_name = maspro_get_filename(UIMAGE_FILE_NUM);
	char *md5sum = maspro_get_md5sum(UIMAGE_FILE_NUM);

	lcd_print("Upgrading %s ... ", file_name);

	/* sanity check */
	if (file_size > 3*MB) {
		lcd_print("\n" PREFIX "Invalid %s, too big.\n", file_name);
		maspro_set_status(UIMAGE_FILE_NUM, FAILED);
		return;
	}

	int count = RETRY_CNT;
	long size, write_size;

retry:

	/* read file */
	size = read_file(PRO_FILE_LOAD_ADDR, file_name, file_size);

	/* md5sum verify */
	if (0 != md5sum_verify(PRO_FILE_LOAD_ADDR, size, UIMAGE_FILE_NUM)) {
		maspro_set_status(UIMAGE_FILE_NUM, FAILED);
		return;
	}

	/* md5sum check */
	if (0 == md5sum_check(UIMAGE_FILE_NUM)) {
		maspro_set_status(UIMAGE_FILE_NUM, NOT_CHANGED);
		lcd_print("Done\n");
		return;
	}

	/* erase nand flash */
	nand_erase(UIMAGE_FILE_NUM);

	/* pad file to nand erase block */
	write_size = pad_file(size);

	/* write file to nand partition */
	nand_write(UIMAGE_FILE_NUM, PRO_FILE_LOAD_ADDR, write_size);

	/*
	 * Verify NAND Content
	 */

	/* read back nand content */
	nand_read(UIMAGE_FILE_NUM, PRO_FILE_LOAD_ADDR, size);

	/* md5sum verify */
	if (0 != md5sum_veriry_nand(PRO_FILE_LOAD_ADDR, size, md5sum)) {
		if (count--) {
			goto retry;
		}
		else {
			maspro_set_status(UIMAGE_FILE_NUM, FAILED);
		}
	}
	else {
		md5sum_save(UIMAGE_FILE_NUM);
	}

	lcd_print("Done\n");
}

static void update_rootfs(void) {
	if (!maspro_isregistered(ROOTFS_FILE_NUM)) {
		return;
	}

	long file_size = maspro_get_filesize(ROOTFS_FILE_NUM);
	char *file_name = maspro_get_filename(ROOTFS_FILE_NUM);
	char *md5sum = maspro_get_md5sum(ROOTFS_FILE_NUM);

	lcd_print("Upgrading %s ... ", file_name);

	/* sanity check */
	if (file_size > 200*MB) {
		lcd_print("\n" PREFIX "Invalid %s, too big.\n", file_name);
		maspro_set_status(ROOTFS_FILE_NUM, FAILED);
		return;
	}

	int count = RETRY_CNT;
	long size, write_size;

retry:

	/* read file */
	size = read_file(PRO_FILE_LOAD_ADDR, file_name, file_size);

	/* md5sum verify */
	if (0 != md5sum_verify(PRO_FILE_LOAD_ADDR, size, ROOTFS_FILE_NUM)) {
		maspro_set_status(ROOTFS_FILE_NUM, FAILED);
		return;
	}

	/* md5sum check */
	if (0 == md5sum_check(ROOTFS_FILE_NUM)) {
		maspro_set_status(ROOTFS_FILE_NUM, NOT_CHANGED);
		lcd_print("Done\n");
		return;
	}

	/* erase nand flash */
	nand_erase(ROOTFS_FILE_NUM);

#if USE_UBI
	/* set ubi part for rootfs */
	run_command(UBI_PART_FOR_ROOTFS, 0);

	/* create rootfs ubi volume */
	run_command(UBI_CREATE_VOL_ROOT, 0);

	/* write file to ubi volume */
	snprintf(cmd_buf, sizeof(cmd_buf), UBI_WRITE_ROOTFS, (unsigned long)PRO_FILE_LOAD_ADDR, size);
	run_command(cmd_buf, 0);
#else
	/* pad file to nand erase block */
	write_size = pad_file(size);

	/* write file to nand partition */
	nand_write(ROOTFS_FILE_NUM, PRO_FILE_LOAD_ADDR, write_size);

	/*
	 * Verify NAND Content
	 */

	/* read back nand content */
	nand_read(ROOTFS_FILE_NUM, PRO_FILE_LOAD_ADDR, size);

	/* md5sum verify */
	if (0 != md5sum_veriry_nand(PRO_FILE_LOAD_ADDR, size, md5sum)) {
		if (count--) {
			goto retry;
		}
		else {
			maspro_set_status(ROOTFS_FILE_NUM, FAILED);
		}
	}
	else {
		md5sum_save(ROOTFS_FILE_NUM);
	}
#endif
	lcd_print("Done\n");
}

typedef void (upgrade_func_t)(void);
static upgrade_func_t *processes[] = {
	update_bootstrap,
	update_uboot,
	update_logo,
	update_dtb,
	update_uimage,
	update_rootfs,
	NULL
};

static void do_upgrade(void) {
	upgrade_func_t **func_ptr;

	/* reset partition table to default */
	run_command(MTDPARTS_DEFAULT, 0);

	for (func_ptr = processes; *func_ptr; ++func_ptr) {
		(*func_ptr)();
	}

	/* check status */
	int i = 0;
	lcd_print(PREFIX "========== SUMMARY ==========\n");
	for (i = 0; i < MAX_FILE_NUM; i++) {
		if (!maspro_isregistered(i)) {
			continue;
		}

		char *file_name = maspro_get_filename(i);
		bool failed = (FAILED == maspro_get_status(i));
		bool not_changed = (NOT_CHANGED == maspro_get_status(i));

		lcd_print("Upgrade %s%s[%s] %s\n", file_name,
				(0 == strcmp(file_name, UIMAGE_FILE)) ? "\t\t" : "\t",
				failed ? "Failed" : "Success",
				not_changed ? "*" : "");

		if (failed) {
			upgrade_ok = false;
		}
	}
}

/*
 * Check upgrade files,
 * if all files get ready, return true; otherwise, return false.
 */
static bool get_files_prepared(void) {
	int i = 0;
	int count = 0;

	for (; i < MAX_FILE_NUM; i++) {
		if(maspro_isregistered(i)) {
			count++;
		}
	}

	if (0 == count) {
		lcd_print(PREFIX "there is no upgrade file.\n");
		return false;
	}

	if (count != TOTAL_UPGRADE_FILES) {
		lcd_print(PREFIX "========== File Missing ==========\n");
		for (i = 0; i < TOTAL_UPGRADE_FILES; i++) {
			bool registered = maspro_isregistered(i);
			char *file_name = registered ? maspro_get_filename(i) : default_filenames[i];

			lcd_print("%s%s[%s]\n", file_name,
					(0 == strcmp(file_name, UIMAGE_FILE)) ? "\t\t" : "\t",
					registered ? "Found" : "Missing");
		}

		return false;
	}

	return true;
}

static int do_massproduction(cmd_tbl_t *cmdtp, int flag, int argc, char *argv[]) {
#if !defined(CONFIG_MMC) && !defined(CONFIG_USB_STORAGE)
	lcd_print(PREFIX "please enable storage device by define CONFIG_MMC or CONFIG_USB_STORAGE!\n");
	return CMD_RET_USAGE;
#else
	/* Clear status */
	memset(maspro_files, 0, sizeof(maspro_files));

	/* Check production mode */
	maspro_user_mode = getenv_ulong("maspro_user_mode", 10, 0);

	/* Search storage device */
	if (-1 == search_storage()) {
		if (0 != maspro_user_mode) {
			setenv_ulong("maspro_user_mode", 0);
			save_env();
		}
		return CMD_RET_FAILURE;
	}

	/* Search upgrade files */
	scan_storage();

	if (0 == maspro_user_mode
			&& 0 == maspro_super_mode) {
		printf(PREFIX "nothing need to do.\n");
		return CMD_RET_SUCCESS;
	}

	/* delay 1s to get around screen blinking */
	mdelay(1000);

	clear_screen();

	bool user_mode = (0 != maspro_user_mode);
	lcd_print(PREFIX "%s\n", user_mode ? "User mode" : "Super mode");

	/* Check md5sum.txt */
	if (!has_chksum) {
		lcd_print(PREFIX CHKSUM_FILE " not found ...\n");
		goto finished;
	}

	/* Check upgrade files */
	if (!get_files_prepared()) {
		goto finished;
	}

	md5sum_parse();
	do_upgrade();

finished:

	/*
	 * restore maspro_user_mode to 0,
	 * so that we will not upgrade the system again when reboot.
	 */
	setenv_ulong("maspro_user_mode", 0);

	/* save environment variables */
	save_env();

	/* hang if failed */
	if (!upgrade_ok) {
		lcd_print(PREFIX "========== ERROR ==========\n"
				"File corrupted, check your files and upgrade again ...\n");
		die_loop();
	}

	if (user_mode) { /* user mode */
		lcd_print(PREFIX "========== Done ==========\n"
				"Reboot in %d seconds ...\n", TIMEOUT);
		mdelay(TIMEOUT * 1000);
		sys_reboot();
	}
	else { /* super mode */
		lcd_print(PREFIX "========== Done ==========\n"
				"Please power off the system and take out of the removable storage ...\n");
		die_loop();
	}

	return CMD_RET_SUCCESS; /* can not reach here */
#endif
}

U_BOOT_CMD(
	maspro, 1, 0, do_massproduction,
	"mass production",
	"use MMC device to mass production"
);

#endif /* CONFIG_CMD_MASSPRODUCTION */
