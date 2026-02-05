rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 52 52 50 50 FF 12 ?? ?? ?? ?? }  // Push edx, push edx, push eax, push eax, call edx (RtlAllocateHeap)
        $pattern1 = { F6 06 0F 84 ?? ?? ?? ?? }         // Test byte [edi], conditional jump (sandbox check)
        $pattern2 = { 56 FF 16 ?? ?? ?? ?? }           // Push esi, call esi (RtlFreeHeap)

    condition:
        any of them
}