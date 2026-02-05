rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 FF 74 ?? 8B 45 C4 8B F3 2B C3 89 45 C0 }  // Test edi, je + context
        $pattern1 = { FF 15 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? 83 26 00 }  // HeapFree call + context
        $pattern2 = { FF 15 ?? ?? ?? ?? 6A ?? 5A 8B CE E8 ?? ?? ?? ?? }  // ExitProcess call + context

    condition:
        any of them
}