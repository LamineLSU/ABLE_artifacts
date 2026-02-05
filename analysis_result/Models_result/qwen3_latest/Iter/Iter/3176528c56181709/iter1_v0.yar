rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { FF D2 5E 5D C3 }  // API call to RtlAllocateHeap + register cleanup
        $pattern1 = { 3D 99 EC 6D 6B 1E 6B 07 55 }  // cmp eax, 0x6B6DEC99h + imul
        $pattern2 = { 8D B0 74 0C 00 00 56 E8 44 09 00 00 }  // lea esi, [eax+0x00000C74h] + call

    condition:
        any of them
}