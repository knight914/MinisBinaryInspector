#include "../MachO.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
static void put(uint8_t *p, uint64_t x, unsigned width, int le) {
    for (unsigned i=0;i<width;i++) { p[le?i:width-1-i]=(uint8_t)x; x>>=8; }
}
static void thin(uint8_t *p,int wide,int le) {
    unsigned h=wide?32:28;
    put(p,0xfeedfaceu+(unsigned)wide,4,le);
    put(p+4,wide?0x100000c:12,4,le);
    put(p+16,1,4,le); put(p+20,8,4,le);
    put(p+h,0x123,4,le); put(p+h+4,8,4,le);
}
static void bad(const uint8_t *p,size_t n) {
    MBIReport r;
    memset(&r,0xff,sizeof r);
    assert(MBIParse(p,n,&r)); assert(r.count==0 && r.slices[0].size==0);
}
int main(void) {
    MBIReport r;
    unsigned prefixes=0;
    for(int w=0;w<2;w++) for(int le=0;le<2;le++) {
        uint8_t p[200]={0};
        unsigned h=w?32:28;
        thin(p,w,le);
        assert(!MBIParse(p,h+8,&r));
        assert(!r.fat && r.count==1 && r.slices[0].wide==w && r.slices[0].little==le);
        assert(r.slices[0].preview[0].kind==0x123 && r.slices[0].preview[0].size==8);
        for(unsigned n=0;n<h+8;n++,prefixes++) bad(p,n);
        put(p+h+4,0,4,le); bad(p,h+8);
        put(p+h+4,7,4,le); bad(p,h+8);
        put(p+h+4,9,4,le); bad(p,h+8);
        put(p+h+4,9,4,le); put(p+20,12,4,le); bad(p,h+12);
        put(p+h+4,8,4,le); bad(p,h+12);
        put(p+16,MBI_MAX_COMMANDS+1,4,le); bad(p,h+12);
        memset(p,0,sizeof p);
        unsigned stride=w?32:20, width=w?8:4;
        put(p,0xcafebabeu+(unsigned)w,4,le); put(p+4,2,4,le);
        for(unsigned i=0;i<2;i++) {
            uint8_t *a=p+8+i*stride;
            unsigned off=80+i*48;
            thin(p+off,1,1);
            put(a,0x100000c,4,le); put(a+8,off,width,le);
            put(a+8+width,40,width,le); put(a+8+2*width,4,4,le);
        }
        assert(!MBIParse(p,168,&r));
        assert(r.fat && r.fat64==w && r.little==le && r.count==2 && r.slices[1].offset==128);
        for(unsigned n=0;n<168;n++,prefixes++) bad(p,n);
        put(p+8+stride+8,80,width,le); bad(p,168);
        put(p+8+stride+8,128,width,le);
        put(p+8+8,81,width,le); bad(p,168);
        put(p+8+8,UINT64_MAX,width,le); bad(p,168);
        put(p+8+8,80,width,le);
        put(p+8+8+width,UINT64_MAX,width,le); bad(p,168);
        put(p+8+8+width,40,width,le);
        put(p+8+8+2*width,64,4,le); bad(p,168);
        put(p+8+8+2*width,4,4,le);
        put(p+8,7,4,le); bad(p,168);
        put(p+4,0,4,le); bad(p,168);
        put(p+4,MBI_MAX_SLICES+1,4,le); bad(p,168);
    }
    uint8_t p[32+25*8]={0};
    bad(p,sizeof p); bad(NULL,32); bad(p,MBI_MAX_BYTES+1u);
    assert(MBIParse(p,sizeof p,NULL));
    thin(p,1,1); put(p+16,25,4,1); put(p+20,25*8,4,1);
    for(unsigned i=0;i<25;i++) put(p+36+i*8,8,4,1);
    assert(!MBIParse(p,sizeof p,&r) && r.slices[0].commandCount==25 && r.slices[0].preview[23].size==8);
    put(p+36+24*8,0,4,1); bad(p,sizeof p);
    printf("PASS: 9 valid synthetic fixtures, %u truncated prefixes, malformed ranges/counts/commands and API guards\n",prefixes);
}
