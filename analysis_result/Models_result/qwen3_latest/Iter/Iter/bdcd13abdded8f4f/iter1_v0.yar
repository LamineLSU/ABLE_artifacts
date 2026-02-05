rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 52 8B 16 50 51 FF D2 5E 5D C3 } // Push edx, mov edx, push eax, push ecx, call edx, pop esi, pop ebp, ret
        $pattern1 = { 0A 60 50 60 } // OR AH, [eax+0x50], pushad
        $pattern2 = { BA 61 55 8B EC 55 55 55 } // mov edx, 0xEC8B5561, push ebp, push ebp, push ebp

    condition:
        any of them
}