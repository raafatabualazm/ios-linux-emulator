/* grok/pcc-vmapple: run the production apple-modern layout+metadata builders
 * against the real cloudOS 23E5207q vphone600 images (platform_vmapple1=on).
 * cc -std=c11 -Wall -Wextra -DAPPLE_MODERN_LAYOUT_STANDALONE -Iinclude \
 *   hw/arm/apple-silicon/modern-boot-layout.c hw/arm/apple-silicon/modern-boot-metadata.c \
 *   tools-grok/pcc/pcc-layout-probe.c -o pcc-layout-probe
 * usage: pcc-layout-probe kc sptm txm dt tc tc2 dram_base_hex dram_size_hex [outdir]
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include "hw/arm/apple-silicon/modern-boot-metadata.h"
static AppleModernBlob rd(const char *p){FILE*f=fopen(p,"rb");AppleModernBlob b={0};if(!f){perror(p);exit(2);}
 fseek(f,0,SEEK_END);long n=ftell(f);fseek(f,0,SEEK_SET);uint8_t*d=malloc(n);if(fread(d,1,n,f)!=(size_t)n)exit(3);fclose(f);b.data=d;b.size=n;return b;}
static void wr(const char*dir,const char*n,const void*d,size_t s){char p[512];snprintf(p,sizeof p,"%s/%s",dir,n);FILE*f=fopen(p,"wb");fwrite(d,1,s,f);fclose(f);}
int main(int argc,char**argv){
 if(argc<9){fprintf(stderr,"usage\n");return 1;}
 AppleModernBootInput in={0};
 in.bootkc=rd(argv[1]);in.sptm=rd(argv[2]);in.txm=rd(argv[3]);in.dtree=rd(argv[4]);in.trustcache=rd(argv[5]);
 if(strcmp(argv[6],"-"))in.cryptex_trustcache=rd(argv[6]);
 in.dram_base=strtoull(argv[7],0,16);in.dram_size=strtoull(argv[8],0,16);in.trustcache_v2=true;in.platform_vmapple1=true;
 const char*cl="serial=3 -v debug=0x2014e wdt=-1";
 AppleModernBootMetadataInput mi={.components=&in,.command_line=cl,.command_line_length=strlen(cl)};
 static AppleModernBootMetadata md; Error*err=NULL;
 if(!apple_modern_boot_metadata_build(&mi,&md,&err)){printf("METADATA FAIL: %s\n",err?err->message:"?");return 4;}
 AppleModernBootLayout*l=&md.layout;
 printf("platform=%s dram=[0x%"PRIx64",+0x%"PRIx64"] virt_base=0x%"PRIx64"\n",l->platform,l->dram_base,l->dram_size,l->virtual_base);
 printf("sptm_entry_phys=0x%"PRIx64" bootargs=0x%"PRIx64" dtree=0x%"PRIx64" (%zu bytes, %u nodes) top_of_kernel_data=0x%"PRIx64" filesets=%u tc_modules=%u\n",
  l->sptm_entry_physical,l->bootargs_physical,l->dtree_physical,md.dtree_size,l->dtree_node_count,l->top_of_kernel_data,l->fileset_entry_count,l->trustcache_module_count);
 const char*nm[3]={"bootkc","sptm","txm"};
 for(int i=0;i<3;i++)printf("image %-6s vbase=0x%"PRIx64" entry=0x%"PRIx64"\n",nm[i],l->image_virtual_base[i],l->image_entry_virtual[i]);
 for(size_t i=0;i<l->region_count;i++)printf("region %-16s 0x%010"PRIx64" +0x%08"PRIx64"\n",l->regions[i].name,l->regions[i].physical_address,l->regions[i].size);
 for(size_t i=0;i<l->copy_count;i++)printf("copy img%d %-16s src+0x%08"PRIx64" len 0x%08"PRIx64" -> 0x%010"PRIx64" (mem 0x%"PRIx64")\n",l->copies[i].image,l->copies[i].segment,l->copies[i].source_offset,l->copies[i].file_size,l->copies[i].physical_address,l->copies[i].memory_size);
 if(argc>9){wr(argv[9],"dtree.prepared",md.dtree,md.dtree_size);wr(argv[9],"bootargs.bin",md.bootargs,sizeof md.bootargs);wr(argv[9],"trustcache.catalog",md.trustcache,md.trustcache_size);}
 return 0;}
