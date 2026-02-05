rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 3D 2D 92 F6 80 74 CF }  // cmp eax, 80F6922Dh + je
        $pattern1 = { E8 44 09 00 00 8B 55 14 }  // call 0041A950h + mov edx, [ebp+14]
        $pattern2 = { 52 8B 16 50 51 FF D2 }  // push edx + mov edx, [esi] + push eax/ecx + call edx

    condition:
        any of them
}