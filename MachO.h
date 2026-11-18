#ifndef MBI_MACHO_H
#define MBI_MACHO_H
#include <stddef.h>
#include <stdint.h>

#define MBI_MAX_BYTES (256u * 1024u * 1024u)
#define MBI_MAX_SLICES 32u
#define MBI_MAX_COMMANDS 4096u
#define MBI_PREVIEW 24u

typedef struct { uint32_t kind, size; } MBICommand;
typedef struct {
    uint64_t offset, size;
    uint32_t cpu, subtype, filetype, flags, commandCount, commandBytes;
    int wide, little;
    MBICommand preview[MBI_PREVIEW];
} MBISlice;
typedef struct {
    unsigned count;
    int fat, fat64, little;
    MBISlice slices[MBI_MAX_SLICES];
} MBIReport;

/* Returns NULL on success, otherwise a static diagnostic and a zero report.
 * The input must remain readable and immutable for the duration of the call.
 */
const char *MBIParse(const uint8_t *data, size_t size, MBIReport *out);
#endif
