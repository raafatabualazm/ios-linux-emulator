/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hw/arm/apple-silicon/modern-smc.h"
static unsigned checks;
#define CHECK(x) do { checks++; if (!(x)) { fprintf(stderr,"line %u: %s\n",__LINE__,#x); exit(1); } } while (0)
static AppleModernBlob read_blob(const char *path)
{
    FILE *f=fopen(path,"rb"); CHECK(f!=NULL); CHECK(!fseek(f,0,SEEK_END));
    long n=ftell(f); CHECK(n>0); CHECK(!fseek(f,0,SEEK_SET));
    uint8_t *data=malloc(n); CHECK(data!=NULL); CHECK(fread(data,1,n,f)==(size_t)n);
    CHECK(!fclose(f)); return (AppleModernBlob){data,n};
}
static void free_error(Error **err) { CHECK(*err!=NULL); free(*err); *err=NULL; }
static void refusal(AppleModernBlob tree, uint64_t dram_base, uint64_t dram_size,
    const AppleModernAddressRange *excl, size_t n)
{
    AppleModernSMCPlan out,before; Error *err=NULL;
    memset(&out,0xa5,sizeof(out)); before=out;
    CHECK(!apple_modern_smc_plan_build(tree,dram_base,dram_size,excl,n,&out,&err));
    CHECK(!memcmp(&before,&out,sizeof(out))); free_error(&err);
}
static AppleModernBlob property(AppleModernBlob tree,const char *node,const char *name)
{
    AppleModernBlob prop; Error *err=NULL;
    CHECK(apple_modern_adt_property(tree,node,name,&prop,&err)); CHECK(err==NULL);
    return prop;
}
static void mutation(AppleModernBlob tree, const char *node,const char *name,size_t off,uint8_t xor)
{
    AppleModernBlob prop=property(tree,node,name); CHECK(off<prop.size);
    uint8_t *p=(uint8_t*)prop.data; p[off]^=xor;
    refusal(tree,UINT64_C(1)<<40,UINT64_C(8)<<30,NULL,0);
    p[off]^=xor;
    AppleModernSMCPlan out; Error *err=NULL;
    CHECK(apple_modern_smc_plan_build(tree,UINT64_C(1)<<40,UINT64_C(8)<<30,NULL,0,&out,&err)); CHECK(err==NULL);
}
int main(int argc,char **argv)
{
    CHECK(argc==3); AppleModernBlob served=read_blob(argv[1]),stock=read_blob(argv[2]);
    const uint64_t dram=UINT64_C(1)<<40, size=UINT64_C(8)<<30;
    AppleModernSMCPlan plan; Error *err=NULL;
    refusal(served,dram,size,NULL,0);
    CHECK(apple_modern_smc_plan_build(stock,dram,size,NULL,0,&plan,&err)); CHECK(err==NULL);
    const uint64_t addresses[]={0x30c600000,0x30c050000,0x30c810000,0x30de00000};
    const uint64_t sizes[]={0x88000,0x4000,0x100,0x100000};
    const uint32_t irqs[]={582,581,584,583};
    for (size_t i=0;i<4;i++) { CHECK(plan.address[i]==addresses[i]); CHECK(plan.size[i]==sizes[i]); CHECK(plan.interrupts[i]==irqs[i]); }
    for (size_t i=0;i<4;i++) {
        refusal(stock,plan.address[i],plan.size[i],NULL,0);
        AppleModernAddressRange r={plan.address[i],plan.size[i]}; refusal(stock,dram,size,&r,1);
        r=(AppleModernAddressRange){plan.address[i]+plan.size[i],8};
        CHECK(apple_modern_smc_plan_build(stock,dram,size,&r,1,&plan,&err)); CHECK(err==NULL);
    }
    AppleModernAddressRange bad={UINT64_MAX-3,8}; refusal(stock,dram,size,&bad,1);
    refusal(stock,dram,size,NULL,1); refusal(stock,UINT64_MAX,8,NULL,0); refusal(stock,dram,0,NULL,0);
    CHECK(!apple_modern_smc_plan_build(stock,dram,size,NULL,0,NULL,&err)); free_error(&err);
    CHECK(!apple_modern_smc_plan_build(stock,dram,size,NULL,0,(AppleModernSMCPlan*)stock.data,&err)); free_error(&err);
    AppleModernAddressRange array[16]={{1,4}};
    CHECK(!apple_modern_smc_plan_build(stock,dram,size,array,1,(AppleModernSMCPlan*)array,&err)); free_error(&err);
    refusal(stock,dram,size,array,APPLE_MODERN_MAX_BOARD_EXCLUSIONS+1);
    for(size_t i=0;i<3;i++) mutation(stock,"/arm-io/smc","reg",i*16+8,1);
    mutation(stock,"/arm-io/smc","compatible",0,1);
    mutation(stock,"/arm-io/smc/iop-smc-nub","compatible",0,1);
    mutation(stock,"/arm-io/smc","role",0,1);
    mutation(stock,"/arm-io/smc","timers-reg-index",0,1);
    mutation(stock,"/arm-io/smc/iop-smc-nub","region-size",0,1);
    /* Duplicate/zero interrupts are refused, independent of line naming. */
    AppleModernBlob irq=property(stock,"/arm-io/smc","interrupts");
    uint8_t original[16]; memcpy(original,irq.data,16); uint8_t *ip=(uint8_t*)irq.data;
    memcpy(ip+4,ip,4); refusal(stock,dram,size,NULL,0); memcpy(ip,original,16);
    memset(ip,0,4); refusal(stock,dram,size,NULL,0); memcpy(ip,original,16);
    size_t n=0; const AppleModernAdtOverride *flags=apple_modern_smc_overrides(&n);
    CHECK(n==2); CHECK(flags==apple_modern_smc_overrides(NULL));
    CHECK(!strcmp(flags[0].name,"pre-loaded")); CHECK(!strcmp(flags[1].name,"running"));
    for(size_t i=0;i<n;i++) { CHECK(!strcmp(flags[i].path,"/arm-io/smc/iop-smc-nub")); CHECK(flags[i].size==4); CHECK(flags[i].value[0]==1); CHECK(!flags[i].value[1]&&!flags[i].value[2]&&!flags[i].value[3]); }
    free((void*)served.data); free((void*)stock.data);
    printf("{\"passed\":true,\"checks\":%u,\"guest_executed\":false,\"firmware_executed\":false}\n",checks);
}
