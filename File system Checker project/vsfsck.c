#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <time.h>

/* Constants */
#define MAGIC_NUMBER 0xD34D
#define BLOCK_SIZE 4096
#define TOTAL_BLOCKS 64
#define INODE_SIZE 256
#define SUPERBLOCK_NUM 0
#define INODE_BITMAP_NUM 1
#define DATA_BITMAP_NUM 2
#define INODE_TABLE_START 3
#define INODE_TABLE_BLOCKS 5
#define DATA_BLOCKS_START 8
#define DATA_BLOCKS_COUNT (TOTAL_BLOCKS - DATA_BLOCKS_START)
#define INODE_COUNT ((INODE_TABLE_BLOCKS * BLOCK_SIZE) / INODE_SIZE)

/* Superblock structure */
typedef struct {
    uint16_t magic;
    uint32_t block_size;
    uint32_t total_blocks;
    uint32_t inode_bitmap_block;
    uint32_t data_bitmap_block;
    uint32_t inode_table_start;
    uint32_t first_data_block;
    uint32_t inode_size;
    uint32_t inode_count;
    uint8_t reserved[4058];
} superblock_t;

/* Inode structure */
typedef struct {
    uint32_t mode;
    uint32_t uid;
    uint32_t gid;
    uint32_t size;
    uint32_t atime;
    uint32_t ctime;
    uint32_t mtime;
    uint32_t dtime;
    uint32_t links_count;
    uint32_t blocks_count;
    uint32_t direct_blocks[10];  // Using 10 direct blocks
    uint32_t single_indirect;
    uint32_t double_indirect;
    uint32_t triple_indirect;
    uint8_t reserved[156];
} inode_t;

/* Global variables */
FILE *fs_file;
superblock_t superblock;
uint8_t *inode_bitmap;
uint8_t *data_bitmap;
inode_t *inodes;
bool *block_refs;  // For tracking block references

/* Helper functions */
bool is_bit_set(uint8_t *bitmap, int bit) {
    return (bitmap[bit / 8] & (1 << (bit % 8))) != 0;
}

void set_bit(uint8_t *bitmap, int bit) {
    bitmap[bit / 8] |= (1 << (bit % 8));
}

void clear_bit(uint8_t *bitmap, int bit) {
    bitmap[bit / 8] &= ~(1 << (bit % 8));
}

bool is_inode_valid(const inode_t *inode) {
    return inode->links_count > 0 && inode->dtime == 0;
}

/* Check if a block number is within valid data block range */
bool is_valid_block(uint32_t block_num) {
    return block_num >= DATA_BLOCKS_START && block_num < TOTAL_BLOCKS;
}

/* Read a block from the file system image */
void read_block(int block_num, void *buffer) {
    fseek(fs_file, block_num * BLOCK_SIZE, SEEK_SET);
    fread(buffer, BLOCK_SIZE, 1, fs_file);
}

/* Write a block to the file system image */
void write_block(int block_num, void *buffer) {
    fseek(fs_file, block_num * BLOCK_SIZE, SEEK_SET);
    fwrite(buffer, BLOCK_SIZE, 1, fs_file);
}

/* Check superblock validity */
bool check_superblock() {
    bool is_valid = true;
    int errors_fixed = 0;
    
    printf("Checking superblock...\n");
    
    if (superblock.magic != MAGIC_NUMBER) {
        printf("Error: Invalid magic number (0x%04X), should be 0x%04X\n", 
               superblock.magic, MAGIC_NUMBER);
        superblock.magic = MAGIC_NUMBER;
        is_valid = false;
        errors_fixed++;
    }
    
    if (superblock.block_size != BLOCK_SIZE) {
        printf("Error: Invalid block size (%u), should be %u\n", 
               superblock.block_size, BLOCK_SIZE);
        superblock.block_size = BLOCK_SIZE;
        is_valid = false;
        errors_fixed++;
    }
    
    if (superblock.total_blocks != TOTAL_BLOCKS) {
        printf("Error: Invalid total blocks (%u), should be %u\n", 
               superblock.total_blocks, TOTAL_BLOCKS);
        superblock.total_blocks = TOTAL_BLOCKS;
        is_valid = false;
        errors_fixed++;
    }
    
    if (superblock.inode_bitmap_block != INODE_BITMAP_NUM) {
        printf("Error: Invalid inode bitmap block (%u), should be %u\n", 
               superblock.inode_bitmap_block, INODE_BITMAP_NUM);
        superblock.inode_bitmap_block = INODE_BITMAP_NUM;
        is_valid = false;
        errors_fixed++;
    }
    
    if (superblock.data_bitmap_block != DATA_BITMAP_NUM) {
        printf("Error: Invalid data bitmap block (%u), should be %u\n", 
               superblock.data_bitmap_block, DATA_BITMAP_NUM);
        superblock.data_bitmap_block = DATA_BITMAP_NUM;
        is_valid = false;
        errors_fixed++;
    }
    
    if (superblock.inode_table_start != INODE_TABLE_START) {
        printf("Error: Invalid inode table start (%u), should be %u\n", 
               superblock.inode_table_start, INODE_TABLE_START);
        superblock.inode_table_start = INODE_TABLE_START;
        is_valid = false;
        errors_fixed++;
    }
    
    if (superblock.first_data_block != DATA_BLOCKS_START) {
        printf("Error: Invalid first data block (%u), should be %u\n", 
               superblock.first_data_block, DATA_BLOCKS_START);
        superblock.first_data_block = DATA_BLOCKS_START;
        is_valid = false;
        errors_fixed++;
    }
    
    if (superblock.inode_size != INODE_SIZE) {
        printf("Error: Invalid inode size (%u), should be %u\n", 
               superblock.inode_size, INODE_SIZE);
        superblock.inode_size = INODE_SIZE;
        is_valid = false;
        errors_fixed++;
    }
    
    if (superblock.inode_count != INODE_COUNT) {
        printf("Error: Invalid inode count (%u), should be %u\n", 
               superblock.inode_count, INODE_COUNT);
        superblock.inode_count = INODE_COUNT;
        is_valid = false;
        errors_fixed++;
    }
    
    if (is_valid) {
        printf("Superblock is valid.\n");
    } else {
        printf("Fixed %d errors in the superblock.\n", errors_fixed);
        // Write corrected superblock back to the image
        write_block(SUPERBLOCK_NUM, &superblock);
    }
    
    return is_valid;
}

/* Process indirect blocks and check for duplicates/references */
void process_indirect_block(uint32_t block_num, int level, bool *duplicate_found, uint8_t *valid_data_bitmap) {
    if (block_num == 0) {
        return;  // Empty block reference
    }
    
    // Check if block is within valid range
    if (!is_valid_block(block_num)) {
        printf("Error: Invalid block reference %u (out of range)\n", block_num);
        return;
    }
    
    // Mark this indirect block as used in the valid bitmap
    set_bit(valid_data_bitmap, block_num);
    
    // Mark block as referenced by an inode and check for duplicates
    if (level == 0) {
        // This is a direct data block
        if (block_refs[block_num]) {
            printf("Error: Block %u is referenced multiple times\n", block_num);
            *duplicate_found = true;
        }
        block_refs[block_num] = true;
    } else {
        // This is an indirect block
        if (block_refs[block_num]) {
            printf("Error: Indirect block %u is referenced multiple times\n", block_num);
            *duplicate_found = true;
        }
        block_refs[block_num] = true;
        
        // Read the indirect block
        uint32_t *indirect_data = malloc(BLOCK_SIZE);
        if (!indirect_data) {
            printf("Error: Memory allocation failed for indirect block data\n");
            return;
        }
        
        read_block(block_num, indirect_data);
        
        // Process each entry in the indirect block
        int entries = BLOCK_SIZE / sizeof(uint32_t);
        for (int i = 0; i < entries; i++) {
            if (indirect_data[i] != 0) {
                // Check if the referenced block is within valid range before processing
                if (is_valid_block(indirect_data[i])) {
                    process_indirect_block(indirect_data[i], level - 1, duplicate_found, valid_data_bitmap);
                } else if (indirect_data[i] != 0) {
                    printf("Error: Invalid block reference %u in indirect block %u (out of range)\n", 
                           indirect_data[i], block_num);
                    // We could fix this by zeroing the reference, but that would require writing back the block
                    // For simplicity, we're just reporting the error here
                }
            }
        }
        
        free(indirect_data);
    }
}

/* Check inode and data bitmap consistency */
void check_bitmaps() {
    printf("Checking bitmap consistency...\n");
    
    // Create temporary bitmaps for validation
    uint8_t *valid_inode_bitmap = calloc(BLOCK_SIZE, 1);
    uint8_t *valid_data_bitmap = calloc(BLOCK_SIZE, 1);
    bool duplicate_found = false;
    int inode_bitmap_errors = 0;
    int data_bitmap_errors = 0;
    
    if (!valid_inode_bitmap || !valid_data_bitmap) {
        printf("Error: Memory allocation failed for validation bitmaps\n");
        if (valid_inode_bitmap) free(valid_inode_bitmap);
        if (valid_data_bitmap) free(valid_data_bitmap);
        return;
    }
    
    // Reset block reference tracking
    memset(block_refs, 0, TOTAL_BLOCKS * sizeof(bool));
    
    // Mark superblock, inode bitmap, data bitmap, and inode table blocks as used
    for (int i = 0; i < DATA_BLOCKS_START; i++) {
        set_bit(valid_data_bitmap, i);
    }
    
    // Check each inode
    for (uint32_t i = 0; i < superblock.inode_count; i++) {
        if (is_inode_valid(&inodes[i])) {
            // Mark this inode as used in our valid bitmap
            set_bit(valid_inode_bitmap, i);
            
            // Process direct blocks
            for (int j = 0; j < 10; j++) {  // Using 10 direct blocks
                uint32_t block_num = inodes[i].direct_blocks[j];
                if (block_num != 0) {
                    if (is_valid_block(block_num)) {
                        process_indirect_block(block_num, 0, &duplicate_found, valid_data_bitmap);
                    } else {
                        printf("Error: Inode %u has invalid direct block reference %u\n", i, block_num);
                        // Note: We'll fix this in the check_bad_blocks function
                    }
                }
            }
            
            // Process single indirect block
            if (inodes[i].single_indirect != 0) {
                if (is_valid_block(inodes[i].single_indirect)) {
                    process_indirect_block(inodes[i].single_indirect, 1, &duplicate_found, valid_data_bitmap);
                } else {
                    printf("Error: Inode %u has invalid single indirect block reference %u\n", 
                           i, inodes[i].single_indirect);
                }
            }
            
            // Process double indirect block
            if (inodes[i].double_indirect != 0) {
                if (is_valid_block(inodes[i].double_indirect)) {
                    process_indirect_block(inodes[i].double_indirect, 2, &duplicate_found, valid_data_bitmap);
                } else {
                    printf("Error: Inode %u has invalid double indirect block reference %u\n", 
                           i, inodes[i].double_indirect);
                }
            }
            
            // Process triple indirect block
            if (inodes[i].triple_indirect != 0) {
                if (is_valid_block(inodes[i].triple_indirect)) {
                    process_indirect_block(inodes[i].triple_indirect, 3, &duplicate_found, valid_data_bitmap);
                } else {
                    printf("Error: Inode %u has invalid triple indirect block reference %u\n", 
                           i, inodes[i].triple_indirect);
                }
            }
        }
    }
    
    // Check inode bitmap consistency
    for (uint32_t i = 0; i < superblock.inode_count; i++) {
        bool actual = is_bit_set(inode_bitmap, i);
        bool expected = is_bit_set(valid_inode_bitmap, i);
        
        if (actual != expected) {
            printf("Error: Inode %u bitmap inconsistency (is %d, should be %d)\n", 
                   i, actual, expected);
            
            if (expected) {
                set_bit(inode_bitmap, i);
            } else {
                clear_bit(inode_bitmap, i);
            }
            
            inode_bitmap_errors++;
        }
    }
    
    // Check data bitmap consistency
    for (uint32_t i = 0; i < superblock.total_blocks; i++) {
        bool actual = is_bit_set(data_bitmap, i);
        bool expected = is_bit_set(valid_data_bitmap, i);
        
        if (actual != expected) {
            printf("Error: Data block %u bitmap inconsistency (is %d, should be %d)\n", 
                   i, actual, expected);
            
            if (expected) {
                set_bit(data_bitmap, i);
            } else {
                clear_bit(data_bitmap, i);
            }
            
            data_bitmap_errors++;
        }
    }
    
    // Report results
    if (inode_bitmap_errors > 0) {
        printf("Fixed %d errors in the inode bitmap.\n", inode_bitmap_errors);
        write_block(INODE_BITMAP_NUM, inode_bitmap);
    } else {
        printf("Inode bitmap is consistent.\n");
    }
    
    if (data_bitmap_errors > 0) {
        printf("Fixed %d errors in the data bitmap.\n", data_bitmap_errors);
        write_block(DATA_BITMAP_NUM, data_bitmap);
    } else {
        printf("Data bitmap is consistent.\n");
    }
    
    if (duplicate_found) {
        printf("Warning: Duplicate block references were found.\n");
        printf("Note: Fixing duplicate references requires more complex repairs not implemented in this checker.\n");
    }
    
    free(valid_inode_bitmap);
    free(valid_data_bitmap);
}

/* Check for bad blocks (references outside valid range) */
void check_bad_blocks() {
    printf("Checking for bad blocks...\n");
    int bad_block_count = 0;
    
    for (uint32_t i = 0; i < superblock.inode_count; i++) {
        if (is_inode_valid(&inodes[i])) {
            // Check direct blocks
            for (int j = 0; j < 10; j++) {  // Using 10 direct blocks
                uint32_t block_num = inodes[i].direct_blocks[j];
                if (block_num != 0 && !is_valid_block(block_num)) {
                    printf("Error: Inode %u has invalid direct block reference %u\n", i, block_num);
                    inodes[i].direct_blocks[j] = 0;  // Clear invalid reference
                    bad_block_count++;
                }
            }
            
            // Check single indirect block
            if (inodes[i].single_indirect != 0 && !is_valid_block(inodes[i].single_indirect)) {
                printf("Error: Inode %u has invalid single indirect block reference %u\n", 
                       i, inodes[i].single_indirect);
                inodes[i].single_indirect = 0;
                bad_block_count++;
            }
            
            // Check double indirect block
            if (inodes[i].double_indirect != 0 && !is_valid_block(inodes[i].double_indirect)) {
                printf("Error: Inode %u has invalid double indirect block reference %u\n", 
                       i, inodes[i].double_indirect);
                inodes[i].double_indirect = 0;
                bad_block_count++;
            }
            
            // Check triple indirect block
            if (inodes[i].triple_indirect != 0 && !is_valid_block(inodes[i].triple_indirect)) {
                printf("Error: Inode %u has invalid triple indirect block reference %u\n", 
                       i, inodes[i].triple_indirect);
                inodes[i].triple_indirect = 0;
                bad_block_count++;
            }
        }
    }
    
    if (bad_block_count > 0) {
        printf("Fixed %d bad block references.\n", bad_block_count);
        
        // Write corrected inodes back to the image
        for (int i = 0; i < INODE_TABLE_BLOCKS; i++) {
            uint32_t inode_block = INODE_TABLE_START + i;
            uint32_t inodes_per_block = BLOCK_SIZE / INODE_SIZE;
            write_block(inode_block, &inodes[i * inodes_per_block]);
        }
    } else {
        printf("No bad blocks found.\n");
    }
}

/* Main function to run the checker */
int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <filesystem_image>\n", argv[0]);
        return 1;
    }
    
    const char *fs_path = argv[1];
    fs_file = fopen(fs_path, "r+b");
    if (!fs_file) {
        perror("Error opening file system image");
        return 1;
    }
    
    printf("VSFS File System Consistency Checker\n");
    printf("====================================\n");
    
    // Read the superblock
    read_block(SUPERBLOCK_NUM, &superblock);
    
    // Allocate memory for bitmaps and inodes
    inode_bitmap = malloc(BLOCK_SIZE);
    data_bitmap = malloc(BLOCK_SIZE);
    inodes = malloc(INODE_COUNT * INODE_SIZE);
    block_refs = calloc(TOTAL_BLOCKS, sizeof(bool));
    
    if (!inode_bitmap || !data_bitmap || !inodes || !block_refs) {
        printf("Error: Memory allocation failed\n");
        // Clean up any successfully allocated memory
        if (inode_bitmap) free(inode_bitmap);
        if (data_bitmap) free(data_bitmap);
        if (inodes) free(inodes);
        if (block_refs) free(block_refs);
        fclose(fs_file);
        return 1;
    }
    
    // Read the bitmaps
    read_block(INODE_BITMAP_NUM, inode_bitmap);
    read_block(DATA_BITMAP_NUM, data_bitmap);
    
    // Read the inodes
    for (int i = 0; i < INODE_TABLE_BLOCKS; i++) {
        uint32_t inode_block = INODE_TABLE_START + i;
        uint32_t inodes_per_block = BLOCK_SIZE / INODE_SIZE;
        read_block(inode_block, &inodes[i * inodes_per_block]);
    }
    
    // Check consistency
    check_superblock();
    check_bad_blocks();
    check_bitmaps();
    
    printf("\nFile system check completed.\n");
    
    // Clean up
    free(inode_bitmap);
    free(data_bitmap);
    free(inodes);
    free(block_refs);
    fclose(fs_file);
    
    return 0;
}
