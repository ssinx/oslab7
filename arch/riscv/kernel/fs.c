#include "fs.h"
#include "buf.h"
#include "defs.h"
#include "slub.h"
#include "task_manager.h"
#include "virtio.h"
#include "vm.h"
#include "mm.h"

// --------------------------------------------------
// ----------- read and write interface -------------

void disk_op(int blockno, uint8_t *data, bool write)
{
    struct buf b;
    b.disk = 0;
    b.blockno = blockno;
    b.data = (uint8_t *)PHYSICAL_ADDR(data);
    virtio_disk_rw((struct buf *)(PHYSICAL_ADDR(&b)), write);
}

#define raw_disk_read(blockno, data) disk_op((blockno), (data), 0)
#define raw_disk_write(blockno, data) disk_op((blockno), (data), 1)

// -------------------------------------------------
// ------------------ your code --------------------

#define SFS_BH_HASH_SHIFT 6
#define SFS_BH_HASH_SIZE (1 << SFS_BH_HASH_SHIFT)
#define SFS_BH_HASH_MASK (SFS_BH_HASH_SIZE - 1)

// 内存中的缓存块头描述符 (Buffer Head)
struct buf_head
{
    uint32_t blockno;      // 块号
    uint8_t *data;         // 指向实际 4KB 数据的指针
    bool dirty;            // 脏位，是否需要写回磁盘
    int ref_count;         // 引用计数，为0时可被回收
    struct list_head list; // 用于链接到哈希表中
};

// 全局 SFS 信息
static struct sfs_super sfs_sb;     // 超级块缓存
static uint8_t *sfs_freemap;        // 位图缓存 (需动态分配)
static bool sfs_sb_dirty = false;   // 超级块/位图是否脏
static bool is_sfs_mounted = false; // 是否挂载/初始化

// 缓存哈希表：blockno -> buf_head
static struct list_head sfs_bh_hash[SFS_BH_HASH_SIZE];

static void *sfs_alloc(uint32_t size)
{
    return kmalloc(size);
}

static void sfs_free(void *ptr)
{
    kfree(ptr);
}

static uint32_t bh_hash_fn(uint32_t blockno)
{
    return blockno & SFS_BH_HASH_MASK;
}

static void sfs_memset(void *dst, int val, int len)
{
    char *ptr = (char *)dst;
    while (len--)
        *ptr++ = val;
}

static void sfs_memcpy(void *dst, const void *src, int len)
{
    char *d = (char *)dst;
    const char *s = (const char *)src;
    while (len--)
        *d++ = *s++;
}

/**
 * 释放一个缓存块的引用
 * 如果引用计数降为0，且没有被钉住(pinned)，在内存紧张时可以回收。
 * 本实验简化处理：引用为0时，如果是脏的，立即写回，并保留在内存中供后续使用，
 * 直到sfs_close或系统退出时统一清理（或者复用）。
 */
void brelse(struct buf_head *bh)
{
    if (!bh)
        return;

    bh->ref_count--;
    if (bh->ref_count < 0)
    {
        printf("[SFS Error] brelse: ref_count < 0 for block %d\n", bh->blockno);
        while (1)
            ;
    }

    // 简单策略：如果脏了且没人用了，可以考虑写回。
    // 但为了性能，通常只在 cache 满了或者 sync 时写回。
    // 这里为了数据安全，我们在引用归零时检查是否脏，脏则写回。
    if (bh->ref_count == 0 && bh->dirty)
    {
        raw_disk_write(bh->blockno, bh->data);
        bh->dirty = false;
        // printf("[SFS] Writeback block %d\n", bh->blockno);
    }
}

/**
 * 获取缓存块
 * 1. 在哈希表中查找
 * 2. 如果没找到，分配新块并从磁盘读取
 * 3. 增加引用计数
 */
struct buf_head *sb_bread(uint32_t blockno)
{
    uint32_t hash_idx = bh_hash_fn(blockno);
    struct buf_head *bh = NULL;
    struct list_head *pos;

    // 1. 查找缓存
    list_for_each(pos, &sfs_bh_hash[hash_idx])
    {
        struct buf_head *tmp = list_entry(pos, struct buf_head, list);
        if (tmp->blockno == blockno)
        {
            bh = tmp;
            break;
        }
    }

    // 2. 缓存命中
    if (bh)
    {
        bh->ref_count++;
        return bh;
    }

    // 3. 缓存未命中，创建新块
    bh = (struct buf_head *)sfs_alloc(sizeof(struct buf_head));
    if (!bh)
    {
        printf("[SFS Error] sb_bread: kmalloc struct failed\n");
        return NULL;
    }

    bh->data = (uint8_t *)sfs_alloc(SFS_BLOCK_SIZE);
    if (!bh->data)
    {
        sfs_free(bh);
        printf("[SFS Error] sb_bread: kmalloc data failed\n");
        return NULL;
    }

    // 读取磁盘数据
    raw_disk_read(blockno, bh->data);

    // 初始化元数据
    bh->blockno = blockno;
    bh->dirty = false;
    bh->ref_count = 1;
    INIT_LIST_HEAD(&bh->list);

    // 加入哈希表
    list_add(&bh->list, &sfs_bh_hash[hash_idx]);

    return bh;
}

/**
 * 标记缓存块为脏
 */
void mark_buffer_dirty(struct buf_head *bh)
{
    if (bh)
    {
        bh->dirty = true;
    }
}

int sfs_init()
{
    if (is_sfs_mounted)
        return 0;

    printf("[SFS] Initializing...\n");

    // 1. 初始化哈希表
    for (int i = 0; i < SFS_BH_HASH_SIZE; i++)
    {
        INIT_LIST_HEAD(&sfs_bh_hash[i]);
    }

    // 2. 读取超级块 (Block 0)
    // 我们可以直接读到全局变量 sfs_sb 中，不需要走 buffer cache，
    // 因为超级块常驻内存且格式固定。
    uint8_t *tmp_buf = (uint8_t *)sfs_alloc(SFS_BLOCK_SIZE);
    raw_disk_read(0, tmp_buf);
    sfs_memcpy(&sfs_sb, tmp_buf, sizeof(struct sfs_super));
    sfs_free(tmp_buf); // 释放临时buffer

    // 检查 Magic Number
    if (sfs_sb.magic != SFS_MAGIC)
    {
        printf("[SFS Error] Invalid Magic Number: 0x%x (Expected 0x%x)\n", sfs_sb.magic, SFS_MAGIC);
        return -1;
    }
    printf("[SFS] Magic verified. Blocks: %d, Unused: %d\n", sfs_sb.blocks, sfs_sb.unused_blocks);

    // 3. 读取 Freemap (Block 2 ~ 2 + N)
    // Freemap 大小计算: sfs_sb.blocks bits.
    // 需要的字节数: sfs_sb.blocks / 8
    // 需要的块数: (blocks/8 + 4095) / 4096
    // 本实验简化处理：假设 Freemap 就在 Block 2，且只有 1 个块 (支持 4096*8 = 32768 blocks，足够大)
    // 实验指导书提到: "第 2 ～ 2 + freemap 块"

    // 分配内存给 freemap
    // 假设最大 blocks 数量不会导致 freemap 超过 4096 字节太多，这里先按1个block处理，或者按实际大小动态分配
    // 为了稳健，我们读取 Freemap 区域的所有块
    int freemap_bytes = (sfs_sb.blocks + 7) / 8;
    int freemap_blocks = (freemap_bytes + SFS_BLOCK_SIZE - 1) / SFS_BLOCK_SIZE;

    // 这里我们只分配必需的大小，或者简单点分配 freemap_blocks * 4096
    sfs_freemap = (uint8_t *)sfs_alloc(freemap_blocks * SFS_BLOCK_SIZE);

    for (int i = 0; i < freemap_blocks; i++)
    {
        raw_disk_read(2 + i, sfs_freemap + i * SFS_BLOCK_SIZE);
    }

    is_sfs_mounted = true;
    printf("[SFS] Mounted successfully.\n");
    return 0;
}

// 将内存中的 Freemap 写回磁盘 (简化策略：全量写回)
// 实际生产中只写回变动的 block
static void sfs_sync_freemap()
{
    int freemap_bytes = (sfs_sb.blocks + 7) / 8;
    int freemap_blocks = (freemap_bytes + SFS_BLOCK_SIZE - 1) / SFS_BLOCK_SIZE;

    for (int i = 0; i < freemap_blocks; i++)
    {
        // Freemap 从 Block 2 开始
        raw_disk_write(2 + i, sfs_freemap + i * SFS_BLOCK_SIZE);
    }
}

// 分配一个新块，返回块号。失败返回 0。
static uint32_t sfs_alloc_block()
{
    uint32_t total_blocks = sfs_sb.blocks;

    // 扫描位图寻找空闲位 (0)
    for (uint32_t i = 0; i < total_blocks; i++)
    {
        uint32_t byte_idx = i / 8;
        uint32_t bit_idx = i % 8;

        if (!((sfs_freemap[byte_idx] >> bit_idx) & 1))
        {
            // 找到空闲块
            sfs_freemap[byte_idx] |= (1 << bit_idx);
            sfs_sb.unused_blocks--;

            // 标记超级块和位图脏
            // 这里为了简化，分配时直接同步位图，虽然慢但安全
            sfs_sync_freemap();

            // 可选：清空新块的内容，防止数据泄露
            // 但我们的 sb_bread 如果读不到会新建并读取旧数据，所以最好清零
            uint8_t *zero_buf = sfs_alloc(SFS_BLOCK_SIZE);
            sfs_memset(zero_buf, 0, SFS_BLOCK_SIZE);
            raw_disk_write(i, zero_buf);
            sfs_free(zero_buf);

            return i;
        }
    }
    printf("[SFS Error] No space left on device\n");
    return 0;
}

// 释放一个块
static void sfs_free_block(uint32_t blockno)
{
    if (blockno >= sfs_sb.blocks)
        return;

    uint32_t byte_idx = blockno / 8;
    uint32_t bit_idx = blockno % 8;

    if ((sfs_freemap[byte_idx] >> bit_idx) & 1)
    {
        sfs_freemap[byte_idx] &= ~(1 << bit_idx);
        sfs_sb.unused_blocks++;
        sfs_sync_freemap();
    }
}

// 辅助：计算所需的总块数 (用于 sfs_write 扩容检查)
static uint32_t sfs_cal_needed_blocks(uint32_t size)
{
    return (size + SFS_BLOCK_SIZE - 1) / SFS_BLOCK_SIZE;
}

/**
 * bmap: 逻辑块号映射到物理块号
 * @inode: 操作的 inode (内存副本或指针，这里为了简单直接传指针，注意并发安全)
 * @bn: 逻辑块号 (Logical Block Number, e.g., 0, 1, 2...)
 * @alloc: 如果对应块不存在，是否分配新块
 * * Return: 物理块号，失败返回 0
 */
static uint32_t sfs_bmap(struct sfs_inode *inode, uint32_t bn, bool alloc)
{
    uint32_t phys_bn;

    // 1. 直接索引 (0 ~ 10)
    if (bn < SFS_NDIRECT)
    {
        phys_bn = inode->direct[bn];
        if (phys_bn == 0 && alloc)
        {
            phys_bn = sfs_alloc_block();
            if (phys_bn == 0)
                return 0; // 分配失败
            inode->direct[bn] = phys_bn;
            inode->blocks++; // 更新 inode 占用的块数记录
        }
        return phys_bn;
    }

    // 2. 间接索引
    // bn 对应的间接索引表中的下标
    uint32_t indirect_idx = bn - SFS_NDIRECT;

    // 一个块能存多少个 uint32_t 索引? 4096 / 4 = 1024
    uint32_t entries_per_block = SFS_BLOCK_SIZE / sizeof(uint32_t);

    if (indirect_idx >= entries_per_block)
    {
        printf("[SFS Error] File too large (indirect limit exceeded)\n");
        return 0;
    }

    // 检查间接索引块本身是否存在
    if (inode->indirect == 0)
    {
        if (alloc)
        {
            uint32_t new_indirect = sfs_alloc_block();
            if (new_indirect == 0)
                return 0;
            inode->indirect = new_indirect;
            inode->blocks++;
        }
        else
        {
            return 0;
        }
    }

    // 读取间接索引块
    struct buf_head *bh = sb_bread(inode->indirect);
    if (!bh)
        return 0;

    uint32_t *idx_table = (uint32_t *)bh->data;
    phys_bn = idx_table[indirect_idx];

    if (phys_bn == 0 && alloc)
    {
        phys_bn = sfs_alloc_block();
        if (phys_bn)
        {
            idx_table[indirect_idx] = phys_bn;
            inode->blocks++;
            mark_buffer_dirty(bh); // 标记间接块脏了
        }
    }

    brelse(bh); // 释放间接索引块的缓存引用
    return phys_bn;
}

/**
 * 在目录 inode 中查找名为 name 的文件
 * @dir_inode: 目录的 Inode
 * @name: 文件名
 * * Return: 找到的 Inode 编号，未找到返回 0
 */
static uint32_t sfs_lookup(struct sfs_inode *dir_inode, const char *name)
{
    if (dir_inode->type != SFS_DIRECTORY)
    {
        printf("[SFS Error] sfs_lookup: not a directory\n");
        return 0;
    }

    uint32_t entries_per_block = SFS_BLOCK_SIZE / sizeof(struct sfs_entry);
    uint32_t total_entries = dir_inode->size / sizeof(struct sfs_entry);

    // 遍历所有逻辑块
    // dir_inode->blocks 并不是很准，因为它包含间接块本身，
    // 最好用 size 计算有多少个有效 entry

    int processed_entries = 0;
    int logical_blk = 0;

    while (processed_entries < total_entries)
    {
        uint32_t phys_blk = sfs_bmap(dir_inode, logical_blk, false);
        if (phys_blk == 0)
        {
            // 理论上 size 还没完，但 map 不到，说明文件系统这块有问题或空洞
            break;
        }

        struct buf_head *bh = sb_bread(phys_blk);
        if (!bh)
            break;

        struct sfs_entry *entries = (struct sfs_entry *)bh->data;
        for (int i = 0; i < entries_per_block && processed_entries < total_entries; i++)
        {
            // 简单的字符串比较
            if (strcmp(entries[i].filename, name) == 0)
            {
                uint32_t found_ino = entries[i].ino;
                brelse(bh);
                return found_ino;
            }
            processed_entries++;
        }

        brelse(bh);
        logical_blk++;
    }

    return 0; // Not found
}

/**
 * 向目录添加一个 entry (name -> ino)
 * 用于创建文件/目录时
 */
static int sfs_dir_link(struct sfs_inode *dir_inode, const char *name, uint32_t ino)
{
    if (dir_inode->type != SFS_DIRECTORY)
        return -1;

    // 检查是否重名 (可选，但在 open 中通常已做)
    if (sfs_lookup(dir_inode, name) != 0)
        return -1; // 已存在

    uint32_t total_entries = dir_inode->size / sizeof(struct sfs_entry);
    uint32_t logical_blk = total_entries * sizeof(struct sfs_entry) / SFS_BLOCK_SIZE;
    uint32_t offset_in_blk = (total_entries * sizeof(struct sfs_entry)) % SFS_BLOCK_SIZE;

    // 获取(或分配)目录数据的最后一块
    uint32_t phys_blk = sfs_bmap(dir_inode, logical_blk, true);
    if (phys_blk == 0)
        return -1; // 空间不足

    struct buf_head *bh = sb_bread(phys_blk);
    if (!bh)
        return -1;

    // 写入新 entry
    struct sfs_entry *entry = (struct sfs_entry *)(bh->data + offset_in_blk);
    entry->ino = ino;
    // 安全的字符串拷贝
    int i = 0;
    for (; i < SFS_MAX_FILENAME_LEN && name[i]; i++)
    {
        entry->filename[i] = name[i];
    }
    entry->filename[i] = '\0';

    mark_buffer_dirty(bh);
    brelse(bh);

    // 更新目录大小
    dir_inode->size += sizeof(struct sfs_entry);
    return 0;
}

// 将内存中的 inode 写回磁盘
// 注意：参数 inode 通常是指向 buffer cache 内部数据的指针
// 所以调用 mark_buffer_dirty(bh) 即可，这里我们假设上层持有 bh
// 如果上层只持有 inode 的值拷贝，我们需要重新 bread
static void sfs_update_inode(uint32_t ino, struct sfs_inode *inode_data)
{
    struct buf_head *bh = sb_bread(ino);
    if (!bh)
        return;

    // Inode 位于块的起始位置 (实验简化设定)
    sfs_memcpy(bh->data, inode_data, sizeof(struct sfs_inode));
    mark_buffer_dirty(bh);
    brelse(bh);
}

/**
 * 在父目录中创建一个新文件/目录
 * @parent_ino: 父目录 Inode 编号
 * @name: 文件名
 * @type: SFS_FILE 或 SFS_DIRECTORY
 * * Return: 新建的 Inode 编号，失败返回 0
 */
static uint32_t sfs_create_inode(uint32_t parent_ino, const char *name, uint16_t type)
{
    // 1. 分配一个新的块作为 Inode 块
    uint32_t new_ino = sfs_alloc_block();
    if (new_ino == 0)
        return 0;

    // 2. 初始化新 Inode
    // 读取新块的 buffer (内容已被 allocator 清零)
    struct buf_head *bh = sb_bread(new_ino);
    struct sfs_inode *new_inode = (struct sfs_inode *)bh->data;

    new_inode->size = 0;
    new_inode->type = type;
    new_inode->links = 1;
    new_inode->blocks = 1;    // 自身占一个块
    new_inode->direct[0] = 0; // 还没有数据块 (对于文件)
    new_inode->indirect = 0;

    // 如果是目录，需要分配一个数据块来存放 "." and ".."
    if (type == SFS_DIRECTORY)
    {
        uint32_t data_blk = sfs_alloc_block();
        if (data_blk == 0)
        {
            brelse(bh);
            // 回滚：释放刚才分配的 inode 块
            sfs_free_block(new_ino);
            return 0;
        }
        new_inode->direct[0] = data_blk;
        new_inode->size = 2 * sizeof(struct sfs_entry); // 初始大小

        // 初始化目录项 "." 和 ".."
        struct buf_head *dbh = sb_bread(data_blk);
        struct sfs_entry *entries = (struct sfs_entry *)dbh->data;

        entries[0].ino = new_ino;
        sfs_memcpy(entries[0].filename, ".", 2);

        entries[1].ino = parent_ino;
        sfs_memcpy(entries[1].filename, "..", 3);

        mark_buffer_dirty(dbh);
        brelse(dbh);
    }

    mark_buffer_dirty(bh);
    brelse(bh);

    // 3. 将新文件链接到父目录
    struct buf_head *parent_bh = sb_bread(parent_ino);
    if (!parent_bh)
        return 0; // Should handle rollback
    struct sfs_inode *parent_inode = (struct sfs_inode *)parent_bh->data;

    if (sfs_dir_link(parent_inode, name, new_ino) != 0)
    {
        // Link 失败，需要清理资源 (略简化)
        brelse(parent_bh);
        return 0;
    }

    // 更新父目录 size 等信息
    mark_buffer_dirty(parent_bh);
    brelse(parent_bh);

    return new_ino;
}

int sfs_open(const char *path, uint32_t flags)
{
    // 0. 确保文件系统已挂载
    if (!is_sfs_mounted)
    {
        if (sfs_init() != 0)
            return -1;
    }

    // 1. 路径检查
    // [修复] 移除 path == NULL 的检查，因为 test5 在地址 0 处存放路径
    if (path[0] != '/')
        return -1;

    // 2. 从根目录开始解析
    uint32_t current_ino = 1; // Root Inode Blockno is 1
    uint32_t parent_ino = 1;

    int i = 1; // 跳过第一个 '/'
    char name[SFS_MAX_FILENAME_LEN + 1];

    while (path[i])
    {
        // 提取路径分量 (Token)
        int j = 0;
        while (path[i] && path[i] != '/' && j < SFS_MAX_FILENAME_LEN)
        {
            name[j++] = path[i++];
        }
        name[j] = '\0';

        // 跳过连续的 '/'
        while (path[i] == '/')
            i++;

        // 在当前目录查找
        struct buf_head *bh = sb_bread(current_ino);
        struct sfs_inode *inode = (struct sfs_inode *)bh->data;

        // 检查当前 inode 是否为目录
        if (inode->type != SFS_DIRECTORY)
        {
            brelse(bh);
            return -1;
        }

        uint32_t next_ino = 0;

        // 如果当前是根目录(1) 且 查找目标是 "..", 则指向自己
        if (current_ino == 1 && strcmp(name, "..") == 0)
        {
            next_ino = 1;
        }
        else
        {
            next_ino = sfs_lookup(inode, name);
        }

        if (next_ino == 0)
        {
            // [修复] 路径分量不存在
            if (flags & SFS_FLAG_WRITE)
            {
                // 如果有写权限，尝试创建
                // 判断是创建目录还是文件：
                // 如果 path[i] != '\0'，说明后面还有内容，当前分量必须是目录
                // 如果 path[i] == '\0'，说明是路径最后一部分，创建为文件
                uint16_t type = (path[i] != '\0') ? SFS_DIRECTORY : SFS_FILE;

                // sfs_create_inode 会负责分配 inode、初始化(如果是目录则建立.和..)、并link到父目录
                next_ino = sfs_create_inode(current_ino, name, type);

                if (next_ino == 0)
                {
                    brelse(bh);
                    return -1; // 创建失败（可能磁盘满）
                }
            }
            else
            {
                // 没写权限且文件不存在 -> 失败
                brelse(bh);
                return -1;
            }
        }

        parent_ino = current_ino;
        current_ino = next_ino;
        brelse(bh);
    }

    // 3. 分配文件描述符
    int fd = -1;
    for (int k = 0; k < 16; k++)
    {
        if (current->fs.fds[k] == NULL)
        {
            fd = k;
            break;
        }
    }
    if (fd == -1)
        return -1; // 进程打开文件过多

    // 4. 初始化 struct file
    struct file *f = (struct file *)sfs_alloc(sizeof(struct file));
    f->ino = current_ino;
    f->parent_ino = parent_ino;
    f->flags = flags;
    f->off = 0;

    // 读取 inode 获取 size
    struct buf_head *bh = sb_bread(current_ino);
    struct sfs_inode *inode = (struct sfs_inode *)bh->data;
    f->size = inode->size;

    // [补充逻辑] 如果以写模式打开文件，且需要截断 (O_TRUNC)，可以在这里处理
    // 本实验暂不要求 O_TRUNC，且 test2/3 是追加或覆盖写，不需清空。

    brelse(bh);

    current->fs.fds[fd] = f;
    return fd;
}

int sfs_close(int fd)
{
    if (fd < 0 || fd >= 16 || current->fs.fds[fd] == NULL)
        return -1;

    struct file *f = current->fs.fds[fd];

    // 我们使用了 Buffer Cache，数据会在 brelse 或者后续被置换时写回
    // 这里不需要显式写回 inode，因为每次 write 操作都更新了 inode 并标记 dirty

    sfs_free(f);
    current->fs.fds[fd] = NULL;
    return 0;
}

int sfs_seek(int fd, int32_t off, int fromwhere)
{
    if (fd < 0 || fd >= 16 || current->fs.fds[fd] == NULL)
        return -1;
    struct file *f = current->fs.fds[fd];

    int32_t new_pos = f->off;

    // 为了获取准确的 size，最好读一下 inode，但为了性能暂时用 f->size
    // 如果需要最强一致性，这里应该 sb_bread 读取 inode->size

    switch (fromwhere)
    {
    case SEEK_SET:
        new_pos = off;
        break;
    case SEEK_CUR:
        new_pos = f->off + off;
        break;
    case SEEK_END:
        new_pos = f->size + off;
        break;
    default:
        return -1;
    }

    if (new_pos < 0 || new_pos > f->size)
        return -1; // 简单起见，不允许 seek 超过 EOF

    f->off = new_pos;
    return 0;
}

int sfs_read(int fd, char *buf, uint32_t len)
{
    if (fd < 0 || fd >= 16 || current->fs.fds[fd] == NULL)
        return -1;
    struct file *f = current->fs.fds[fd];

    // 获取 inode
    struct buf_head *ibh = sb_bread(f->ino);
    struct sfs_inode *inode = (struct sfs_inode *)ibh->data;

    // 检查越界
    if (f->off >= inode->size)
    {
        brelse(ibh);
        return 0;
    }
    if (f->off + len > inode->size)
    {
        len = inode->size - f->off;
    }

    uint32_t read_bytes = 0;
    uint32_t current_off = f->off;

    while (len > 0)
    {
        uint32_t logical_blk = current_off / SFS_BLOCK_SIZE;
        uint32_t offset_in_blk = current_off % SFS_BLOCK_SIZE;
        uint32_t bytes_to_read = SFS_BLOCK_SIZE - offset_in_blk;
        if (bytes_to_read > len)
            bytes_to_read = len;

        // 获取物理块号 (read 不 alloc)
        uint32_t phys_blk = sfs_bmap(inode, logical_blk, false);

        if (phys_blk != 0)
        {
            struct buf_head *dbh = sb_bread(phys_blk);
            // 拷贝数据到用户 buffer
            sfs_memcpy(buf + read_bytes, dbh->data + offset_in_blk, bytes_to_read);
            brelse(dbh);
        }
        else
        {
            // 稀疏文件/空洞，填 0
            sfs_memset(buf + read_bytes, 0, bytes_to_read);
        }

        read_bytes += bytes_to_read;
        current_off += bytes_to_read;
        len -= bytes_to_read;
    }

    f->off = current_off;
    brelse(ibh);
    return read_bytes;
}

int sfs_write(int fd, char *buf, uint32_t len)
{
    if (fd < 0 || fd >= 16 || current->fs.fds[fd] == NULL)
        return -1;
    struct file *f = current->fs.fds[fd];

    if (!(f->flags & SFS_FLAG_WRITE))
        return -1;

    struct buf_head *ibh = sb_bread(f->ino);
    struct sfs_inode *inode = (struct sfs_inode *)ibh->data;

    uint32_t written_bytes = 0;
    uint32_t current_off = f->off;

    while (len > 0)
    {
        uint32_t logical_blk = current_off / SFS_BLOCK_SIZE;
        uint32_t offset_in_blk = current_off % SFS_BLOCK_SIZE;
        uint32_t bytes_to_write = SFS_BLOCK_SIZE - offset_in_blk;
        if (bytes_to_write > len)
            bytes_to_write = len;

        // 获取物理块号 (alloc = true)
        uint32_t phys_blk = sfs_bmap(inode, logical_blk, true);
        if (phys_blk == 0)
        {
            // 磁盘满
            break;
        }

        struct buf_head *dbh = sb_bread(phys_blk);
        // 从用户 buffer 拷贝到缓存
        sfs_memcpy(dbh->data + offset_in_blk, buf + written_bytes, bytes_to_write);
        mark_buffer_dirty(dbh);
        brelse(dbh);

        written_bytes += bytes_to_write;
        current_off += bytes_to_write;
        len -= bytes_to_write;
    }

    // 更新 offset
    f->off = current_off;

    // 如果文件变大，更新 inode size
    if (f->off > inode->size)
    {
        inode->size = f->off;
        mark_buffer_dirty(ibh); // inode 变脏了
    }
    else
    {
        // 如果我们修改了 bmap (分配了新块)，inode 里的 blocks/direct/indirect 也会变
        // sfs_bmap 是直接修改内存中 inode 指针指向的数据，所以 ibh 其实已经脏了
        // 我们需要确保 mark_buffer_dirty
        mark_buffer_dirty(ibh);
    }

    // 更新 file 结构体中的 cache size
    f->size = inode->size;

    brelse(ibh);
    return written_bytes;
}

int sfs_get_files(const char *path, char *files[])
{
    if (!is_sfs_mounted)
        sfs_init();

    // 1. 打开目录获取 fd (复用 sfs_open 的逻辑)
    // 这里为了避免文件描述符泄露，我们手动查找 inode
    // 简化处理：直接调用 open 然后 read，最后 close

    int fd = sfs_open(path, SFS_FLAG_READ);
    if (fd < 0)
        return -1;

    struct file *f = current->fs.fds[fd];
    struct buf_head *ibh = sb_bread(f->ino);
    struct sfs_inode *inode = (struct sfs_inode *)ibh->data;

    if (inode->type != SFS_DIRECTORY)
    {
        brelse(ibh);
        sfs_close(fd);
        return 0;
    }

    int count = 0;
    int entry_count = inode->size / sizeof(struct sfs_entry);
    int entries_per_block = SFS_BLOCK_SIZE / sizeof(struct sfs_entry);

    // 遍历所有数据块
    int processed = 0;
    int logical_blk = 0;

    while (processed < entry_count)
    {
        uint32_t phys_blk = sfs_bmap(inode, logical_blk++, false);
        if (phys_blk == 0)
            break;

        struct buf_head *dbh = sb_bread(phys_blk);
        struct sfs_entry *entries = (struct sfs_entry *)dbh->data;

        for (int i = 0; i < entries_per_block && processed < entry_count; i++)
        {
            // 拷贝文件名到用户数组
            // 注意：files[] 是用户态指针，还是内核态的 char* 数组?
            // 根据 syscall.c 的实现，files 是 (char**)arg1，是一个指针数组。
            // 我们假设 files[count] 指向了足够大的空间 (test5.c 中分配了)

            sfs_memcpy(files[count], entries[i].filename, SFS_MAX_FILENAME_LEN + 1);
            count++;
            processed++;
        }
        brelse(dbh);
    }

    brelse(ibh);
    sfs_close(fd);
    return count;
}