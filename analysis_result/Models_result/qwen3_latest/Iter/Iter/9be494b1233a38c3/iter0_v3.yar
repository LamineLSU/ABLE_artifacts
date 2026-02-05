rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 50 FF 15 ?? ?? ?? ?? 85 C0 75 07 50 FF 15 ?? ?? ?? ?? }  // VirtualAllocExNuma test + jne
        $pattern1 = { 56 68 ?? ?? ?? ?? 6A 00 FF 15 ?? ?? ?? ?? 85 C0 }       // VirtualAlloc size check + test
        $pattern2 = { 5B 68 ?? ?? ?? ?? 56 57 FF 15 ?? ?? ?? ?? 85 C9 }       // Test ecx + VirtualFree call

    condition:
        any of them
}