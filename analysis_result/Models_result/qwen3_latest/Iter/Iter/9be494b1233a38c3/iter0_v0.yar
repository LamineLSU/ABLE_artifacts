rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { FF 15 ?? ?? ?? ?? 83 F8 11 }  // VirtualAlloc + EAX comparison
        $pattern1 = { FF 15 ?? ?? ?? ?? 85 C0 75 07 }  // VirtualAllocExNuma + test/jne
        $pattern2 = { FF 15 ?? ?? ?? ?? E9 ?? ?? ?? ?? }  // ExitProcess call + jmp to start

    condition:
        any of them
}