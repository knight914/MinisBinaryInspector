#include "MachO.h"
#include <string.h>

static uint64_t readn(const uint8_t *p, unsigned n, int little) {
    uint64_t v = 0;
    for (unsigned i = 0; i < n; ++i)
        v = (v << 8) | p[little ? n - 1 - i : i];
    return v;
}
#define U32(p, le) ((uint32_t)readn((p), 4, (le)))

static const char *thin(const uint8_t *p, size_t n, MBISlice *s) {
    if (n < 4) return "Truncated Mach-O magic";
    switch (U32(p, 0)) {
        case 0xfeedface: break;
        case 0xcefaedfe: s->little = 1; break;
        case 0xfeedfacf: s->wide = 1; break;
        case 0xcffaedfe: s->little = s->wide = 1; break;
        default: return "Not a thin Mach-O";
    }
    int le = s->little;
    size_t h = s->wide ? 32 : 28;
    if (n < h) return "Truncated Mach-O header";
    s->cpu = U32(p+4, le);
    s->subtype = U32(p+8, le);
    s->filetype = U32(p+12, le);
    s->commandCount = U32(p+16, le);
    s->commandBytes = U32(p+20, le);
    s->flags = U32(p+24, le);
    size_t left = s->commandBytes;
    if (left > n-h || s->commandCount > MBI_MAX_COMMANDS || s->commandCount > left/8)
        return "Invalid load-command table bounds or count";
    p += h;
    for (uint32_t i = 0; i < s->commandCount; ++i) {
        if (left < 8) return "Truncated load-command header";
        uint32_t size = U32(p+4, le);
        if (size < 8 || size > left || size % (s->wide ? 8u : 4u))
            return "Invalid load-command size or alignment";
        if (i < MBI_PREVIEW) s->preview[i] = (MBICommand){U32(p, le), size};
        left -= size;
        p += size;
    }
    return left ? "Load-command sizes do not match sizeofcmds" : NULL;
}

const char *MBIParse(const uint8_t *data, size_t size, MBIReport *out) {
    if (!out) return "Missing report";
    memset(out, 0, sizeof(*out));
    if (!data || size < 4 || size > MBI_MAX_BYTES) return "Invalid file size";
    MBIReport r = {0};
    uint32_t magic = U32(data, 0);
    r.fat64 = magic == 0xcafebabf || magic == 0xbfbafeca;
    r.fat = r.fat64 || magic == 0xcafebabe || magic == 0xbebafeca;
    const char *err;
    if (!r.fat) {
        r.count = 1;
        r.slices[0].size = size;
        err = thin(data, size, &r.slices[0]);
        if (err) return err;
    } else {
        if (size < 8) return "Truncated universal header";
        int le = r.little = magic == 0xbfbafeca || magic == 0xbebafeca;
        unsigned stride = r.fat64 ? 32 : 20, width = r.fat64 ? 8 : 4;
        r.count = U32(data+4, le);
        if (!r.count || r.count > MBI_MAX_SLICES || r.count > (size-8)/stride)
            return "Invalid universal slice count or table bounds";
        size_t tableEnd = 8 + r.count*stride;
        for (unsigned i = 0; i < r.count; ++i) {
            const uint8_t *a = data + 8 + i*stride;
            uint64_t off = readn(a+8, width, le), len = readn(a+8+width, width, le);
            uint32_t align = U32(a+8+2*width, le);
            if (off < tableEnd || off > size || !len || len > size-off ||
                align >= 64 || (off & ((UINT64_C(1) << align)-1)))
                return "Invalid universal slice range or alignment";
            for (unsigned j = 0; j < i; ++j) {
                const MBISlice *b = &r.slices[j];
                if (off < b->offset+b->size && b->offset < off+len)
                    return "Overlapping universal slices";
            }
            MBISlice *s = &r.slices[i];
            s->offset = off;
            s->size = len;
            err = thin(data+(size_t)off, (size_t)len, s);
            if (err) return err;
            if (s->cpu != U32(a, le) || s->subtype != U32(a+4, le))
                return "Universal entry CPU metadata does not match slice";
        }
    }
    *out = r;
    return NULL;
}
