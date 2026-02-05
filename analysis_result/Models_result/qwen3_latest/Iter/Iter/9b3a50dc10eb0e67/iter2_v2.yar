rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { C1 E8 08 A8 01 75 10 }  // shr eax, 08h + test al, 01h + jne
        $pattern1 = { FF 15 ?? ?? ?? ?? }  // call dword ptr [address]
        $pattern2 = { E8 0B 00 00 00 FF 15 A8 01 B8 00 }  // call + call to function pointer

    condition:
        any of them
}