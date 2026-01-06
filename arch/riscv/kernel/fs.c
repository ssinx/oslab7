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

// 缓存块头
struct buf_head
{
    uint32_t blockno;      // 块号
    uint8_t *data;         // 指向实际 4KB 数据的指针
    bool dirty;            // 脏位
    int ref_count;         // 硬链接计数
    struct list_head list; // 用于链接到哈希表中
};

// 全局 SFS 信息
static struct sfs_super sfs_sb;     // 超级块缓存
static uint8_t *sfs_freemap;        // 位图缓存
static bool sfs_sb_dirty = false;   // 超级块/位图是否脏
static bool is_sfs_mounted = false; // 是否已初始化

// 缓存哈希表 blockno -> buf_head
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

//block release释放
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

    //引用为零，如果是脏的就要写回，不脏就不用管了
    if (bh->ref_count == 0 && bh->dirty)
    {
        raw_disk_write(bh->blockno, bh->data);
        bh->dirty = false;
        // printf("[SFS] Writeback block %d\n", bh->blockno);
    }
}

//看blockno是否在缓存中
struct buf_head *sb_bread(uint32_t blockno)
{
    uint32_t hash_idx = bh_hash_fn(blockno); //算哈希
    struct buf_head *bh = NULL;
    struct list_head *pos;

    list_for_each(pos, &sfs_bh_hash[hash_idx])
    {
        struct buf_head *tmp = list_entry(pos, struct buf_head, list);
        if (tmp->blockno == blockno)
        {
            bh = tmp;
            break;
        }
    }

    //在缓存中
    if (bh)
    {
        bh->ref_count++;
        return bh;
    }

    //不在就建一个新块
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

    //把磁盘数据读进内存然后初始化
    raw_disk_read(blockno, bh->data);
    bh->blockno = blockno;
    bh->dirty = false;
    bh->ref_count = 1;
    INIT_LIST_HEAD(&bh->list);

    //加进哈希表
    list_add(&bh->list, &sfs_bh_hash[hash_idx]);

    return bh;
}

//标记缓存块脏了
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

    //初始化哈希表
    for (int i = 0; i < SFS_BH_HASH_SIZE; i++)
        INIT_LIST_HEAD(&sfs_bh_hash[i]);

    //block0
    uint8_t *tmp_buf = (uint8_t *)sfs_alloc(SFS_BLOCK_SIZE);
    raw_disk_read(0, tmp_buf);
    sfs_memcpy(&sfs_sb, tmp_buf, sizeof(struct sfs_super));
    sfs_free(tmp_buf);

    //检查是sfs系统
    if (sfs_sb.magic != SFS_MAGIC)
    {
        printf("[SFS Error] Invalid Magic Number: 0x%x (Expected 0x%x)\n", sfs_sb.magic, SFS_MAGIC);
        return -1;
    }
    printf("[SFS] Magic verified. Blocks: %d, Unused: %d\n", sfs_sb.blocks, sfs_sb.unused_blocks);

    //freemap，都做上取整
    int freemap_bytes = (sfs_sb.blocks + 7) / 8;
    int freemap_blocks = (freemap_bytes + SFS_BLOCK_SIZE - 1) / SFS_BLOCK_SIZE;

    sfs_freemap = (uint8_t *)sfs_alloc(freemap_blocks * SFS_BLOCK_SIZE);

    for (int i = 0; i < freemap_blocks; i++)
        raw_disk_read(2 + i, sfs_freemap + i * SFS_BLOCK_SIZE);

    is_sfs_mounted = true;
    printf("[SFS] Mounted successfully.\n");
    return 0;
}

//把freemap写回
static void sfs_sync_freemap()
{
    int freemap_bytes = (sfs_sb.blocks + 7) / 8;
    int freemap_blocks = (freemap_bytes + SFS_BLOCK_SIZE - 1) / SFS_BLOCK_SIZE;

    for (int i = 0; i < freemap_blocks; i++)
        raw_disk_write(2 + i, sfs_freemap + i * SFS_BLOCK_SIZE);
}

//分配新块
static uint32_t sfs_alloc_block()
{
    uint32_t total_blocks = sfs_sb.blocks;

    //扫freemamp
    for (uint32_t i = 0; i < total_blocks; i++)
    {
        uint32_t byte_idx = i / 8;
        uint32_t bit_idx = i % 8;

        if (!((sfs_freemap[byte_idx] >> bit_idx) & 1))//发现这一位是0，说明空闲
        {
            sfs_freemap[byte_idx] |= (1 << bit_idx);//置1
            sfs_sb.unused_blocks--;

            sfs_sync_freemap();//把freemap写回，实现同步

            //通过写保证新块全零
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

//释放块
static void sfs_free_block(uint32_t blockno)
{
    if (blockno >= sfs_sb.blocks)
        return;

    uint32_t byte_idx = blockno / 8;
    uint32_t bit_idx = blockno % 8;

    if ((sfs_freemap[byte_idx] >> bit_idx) & 1)
    {
        sfs_freemap[byte_idx] &= ~(1 << bit_idx);//更新freemap
        sfs_sb.unused_blocks++;
        sfs_sync_freemap();
    }
}

// 辅助：计算所需的总块数 (用于 sfs_write 扩容检查)
static uint32_t sfs_cal_needed_blocks(uint32_t size)
{
    return (size + SFS_BLOCK_SIZE - 1) / SFS_BLOCK_SIZE;
}

//把逻辑块号转换成物理块号
static uint32_t sfs_bmap(struct sfs_inode *inode, uint32_t bn, bool alloc)
{
    uint32_t phys_bn;

    //在直接索引的范围内
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

    //间接索引
    uint32_t indirect_idx = bn - SFS_NDIRECT;

    // 一个块能存多少个索引? 4096 / 4 = 1024
    uint32_t entries_per_block = SFS_BLOCK_SIZE / sizeof(uint32_t);

    if (indirect_idx >= entries_per_block)
    {
        printf("[SFS Error] File too large (indirect limit exceeded)\n");
        return 0;
    }

    //如果还没出现过简介索引块，先分配一个
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
            return 0;
    }

    //读间接索引块
    struct buf_head *bh = sb_bread(inode->indirect);
    if (!bh)
        return 0;

    uint32_t *idx_table = (uint32_t *)bh->data;
    phys_bn = idx_table[indirect_idx];

    if (phys_bn == 0 && alloc)//没有这个块就分配一个
    {
        phys_bn = sfs_alloc_block();
        if (phys_bn)
        {
            idx_table[indirect_idx] = phys_bn;
            inode->blocks++;
            mark_buffer_dirty(bh);//分配了之后，原来的间接块脏了
        }
    }

    brelse(bh);//读完及时释放
    return phys_bn;
}

//在目录里找name文件
static uint32_t sfs_lookup(struct sfs_inode *dir_inode, const char *name)
{
    if (dir_inode->type != SFS_DIRECTORY)
    {
        printf("[SFS Error] sfs_lookup: not a directory\n");
        return 0;
    }

    uint32_t entries_per_block = SFS_BLOCK_SIZE / sizeof(struct sfs_entry);
    uint32_t total_entries = dir_inode->size / sizeof(struct sfs_entry);

    int processed_entries = 0;
    int logical_blk = 0;

    //遍历
    while (processed_entries < total_entries)
    {
        uint32_t phys_blk = sfs_bmap(dir_inode, logical_blk, false);
        if (phys_blk == 0)
            // 理论上size还没完，但map不到，说明文件系统这里有个洞
            break;

        struct buf_head *bh = sb_bread(phys_blk);
        if (!bh)
            break;

        struct sfs_entry *entries = (struct sfs_entry *)bh->data;
        for (int i = 0; i < entries_per_block && processed_entries < total_entries; i++)
        {
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

//创建一个entry
static int sfs_dir_link(struct sfs_inode *dir_inode, const char *name, uint32_t ino)
{
    if (dir_inode->type != SFS_DIRECTORY)
        return -1;

    //检查重名
    if (sfs_lookup(dir_inode, name) != 0)
        return -1;

    uint32_t total_entries = dir_inode->size / sizeof(struct sfs_entry);
    uint32_t logical_blk = total_entries * sizeof(struct sfs_entry) / SFS_BLOCK_SIZE;
    uint32_t offset_in_blk = (total_entries * sizeof(struct sfs_entry)) % SFS_BLOCK_SIZE;

    //目录数据的最后一块
    uint32_t phys_blk = sfs_bmap(dir_inode, logical_blk, true);
    if (phys_blk == 0)
        return -1; //空间不足

    struct buf_head *bh = sb_bread(phys_blk);
    if (!bh)
        return -1;

    //写入新entry
    struct sfs_entry *entry = (struct sfs_entry *)(bh->data + offset_in_blk);
    entry->ino = ino;
    //拷贝文件名
    int i = 0;
    for (; i < SFS_MAX_FILENAME_LEN && name[i]; i++)
    {
        entry->filename[i] = name[i];
    }
    entry->filename[i] = '\0';

    mark_buffer_dirty(bh);
    brelse(bh);

    //更新目录大小
    dir_inode->size += sizeof(struct sfs_entry);
    return 0;
}

//将内存中的inode写回
static void sfs_update_inode(uint32_t ino, struct sfs_inode *inode_data)
{
    struct buf_head *bh = sb_bread(ino);
    if (!bh)
        return;

    //inode在块的起始位置
    sfs_memcpy(bh->data, inode_data, sizeof(struct sfs_inode));
    mark_buffer_dirty(bh);
    brelse(bh);
}

//创建文件/目录
static uint32_t sfs_create_inode(uint32_t parent_ino, const char *name, uint16_t type)
{
    //分配一个块作为inode
    uint32_t new_ino = sfs_alloc_block();
    if (new_ino == 0)
        return 0;

    //初始化新inode
    //读新块的buffer
    struct buf_head *bh = sb_bread(new_ino);
    struct sfs_inode *new_inode = (struct sfs_inode *)bh->data;

    new_inode->size = 0;
    new_inode->type = type;
    new_inode->links = 1;
    new_inode->blocks = 1;    //自己
    new_inode->direct[0] = 0; //还没有数据块
    new_inode->indirect = 0;

    //如果是目录，需要分配一个数据块来存放.和..
    if (type == SFS_DIRECTORY)
    {
        uint32_t data_blk = sfs_alloc_block();
        if (data_blk == 0)
        {
            brelse(bh);
            //释放刚才分配的inode块
            sfs_free_block(new_ino);
            return 0;
        }
        new_inode->direct[0] = data_blk;
        new_inode->size = 2 * sizeof(struct sfs_entry);//初始大小

        //初始化.和..
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

    //将新文件链接到父目录
    struct buf_head *parent_bh = sb_bread(parent_ino);
    if (!parent_bh)
        return 0;
    struct sfs_inode *parent_inode = (struct sfs_inode *)parent_bh->data;

    if (sfs_dir_link(parent_inode, name, new_ino) != 0)
    {
        //Link失败
        brelse(parent_bh);
        return 0;
    }

    //更新父目录
    mark_buffer_dirty(parent_bh);
    brelse(parent_bh);

    return new_ino;
}

//打开文件
int sfs_open(const char *path, uint32_t flags)
{
    if (!is_sfs_mounted)
    {
        if (sfs_init() != 0)
            return -1;
    }

    if (path[0] != '/')
        return -1;

    uint32_t current_ino = 1;
    uint32_t parent_ino = 1;

    int i = 1;
    char name[SFS_MAX_FILENAME_LEN + 1];

    while (path[i])
    {
        int j = 0;
        while (path[i] && path[i] != '/' && j < SFS_MAX_FILENAME_LEN)
            name[j++] = path[i++];

        name[j] = '\0';
        while (path[i] == '/')
            i++;

        struct buf_head *bh = sb_bread(current_ino);
        struct sfs_inode *inode = (struct sfs_inode *)bh->data;

        if (inode->type != SFS_DIRECTORY)
        {
            brelse(bh);
            return -1;
        }

        uint32_t next_ino = 0;

        //特判根目录的..
        if (current_ino == 1 && strcmp(name, "..") == 0)
            next_ino = 1;
        else
            next_ino = sfs_lookup(inode, name);

        brelse(bh);

        if (next_ino == 0)
        {
            if (flags & SFS_FLAG_WRITE)
            {
                //判断是否是路径最后一段
                //path[i] != '\0'说明是中间目录，需要创建目录
                uint16_t type = (path[i] != '\0') ? SFS_DIRECTORY : SFS_FILE;

                next_ino = sfs_create_inode(current_ino, name, type);
                if (next_ino == 0)
                    return -1;
            }
            else
                return -1;
        }

        parent_ino = current_ino;
        current_ino = next_ino;
    }

    int fd = -1;
    for (int k = 0; k < 16; k++)
        if (current->fs.fds[k] == NULL)
        {
            fd = k;
            break;
        }
    if (fd == -1)
        return -1;

    struct file *f = (struct file *)sfs_alloc(sizeof(struct file));
    f->ino = current_ino;
    f->parent_ino = parent_ino;
    f->flags = flags;
    f->off = 0;

    // 读取inode获取size
    struct buf_head *bh = sb_bread(current_ino);
    struct sfs_inode *inode = (struct sfs_inode *)bh->data;
    f->size = inode->size;
    brelse(bh);

    current->fs.fds[fd] = f;
    return fd;
}

int sfs_close(int fd)
{
    if (fd < 0 || fd >= 16 || current->fs.fds[fd] == NULL)
        return -1;

    struct file *f = current->fs.fds[fd];

    //这里不需要显式写回inode，因为每次write操作都更新了inode并标记dirty

    sfs_free(f);
    current->fs.fds[fd] = NULL;
    return 0;
}

//移动文件指针
int sfs_seek(int fd, int32_t off, int fromwhere)
{
    if (fd < 0 || fd >= 16 || current->fs.fds[fd] == NULL)
        return -1;
    struct file *f = current->fs.fds[fd];

    int32_t new_pos = f->off;

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
        return -1;

    f->off = new_pos;
    return 0;
}

int sfs_read(int fd, char *buf, uint32_t len)
{
    if (fd < 0 || fd >= 16 || current->fs.fds[fd] == NULL)
        return -1;
    struct file *f = current->fs.fds[fd];

    struct buf_head *ibh = sb_bread(f->ino);
    struct sfs_inode *inode = (struct sfs_inode *)ibh->data;

    //越界
    if (f->off >= inode->size)
    {
        brelse(ibh);
        return 0;
    }
    if (f->off + len > inode->size)
        len = inode->size - f->off;

    uint32_t read_bytes = 0;
    uint32_t current_off = f->off;

    while (len > 0)
    {
        uint32_t logical_blk = current_off / SFS_BLOCK_SIZE;
        uint32_t offset_in_blk = current_off % SFS_BLOCK_SIZE;
        uint32_t bytes_to_read = SFS_BLOCK_SIZE - offset_in_blk;
        if (bytes_to_read > len)
            bytes_to_read = len;

        uint32_t phys_blk = sfs_bmap(inode, logical_blk, false);

        if (phys_blk != 0)
        {
            struct buf_head *dbh = sb_bread(phys_blk);
            sfs_memcpy(buf + read_bytes, dbh->data + offset_in_blk, bytes_to_read);
            brelse(dbh);
        }
        else
            sfs_memset(buf + read_bytes, 0, bytes_to_read);

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

        uint32_t phys_blk = sfs_bmap(inode, logical_blk, true);
        if (phys_blk == 0)
            break;//磁盘满了

        struct buf_head *dbh = sb_bread(phys_blk);
        sfs_memcpy(dbh->data + offset_in_blk, buf + written_bytes, bytes_to_write);
        mark_buffer_dirty(dbh);
        brelse(dbh);

        written_bytes += bytes_to_write;
        current_off += bytes_to_write;
        len -= bytes_to_write;
    }

    f->off = current_off;

    //如果文件变大了，要更新inode size
    if (f->off > inode->size)
    {
        inode->size = f->off;
        mark_buffer_dirty(ibh);
    }
    else
        mark_buffer_dirty(ibh);

    f->size = inode->size;

    brelse(ibh);
    return written_bytes;
}

int sfs_get_files(const char *path, char *files[])
{
    if (!is_sfs_mounted)
        sfs_init();

    //打开目录
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

    int processed = 0;
    int logical_blk = 0;

    while (processed < entry_count)
    {
        //读目录数据块
        uint32_t phys_blk = sfs_bmap(inode, logical_blk++, false);
        if (phys_blk == 0)
            break;

        struct buf_head *dbh = sb_bread(phys_blk);
        struct sfs_entry *entries = (struct sfs_entry *)dbh->data;

        for (int i = 0; i < entries_per_block && processed < entry_count; i++)
        {
            //过滤掉inode为0的空项（如果存在）
            if (entries[i].ino != 0)
            {
                sfs_memcpy(files[count], entries[i].filename, SFS_MAX_FILENAME_LEN + 1);
                count++;
            }
            processed++;
        }
        brelse(dbh);
    }

    brelse(ibh);
    sfs_close(fd);
    return count;
}