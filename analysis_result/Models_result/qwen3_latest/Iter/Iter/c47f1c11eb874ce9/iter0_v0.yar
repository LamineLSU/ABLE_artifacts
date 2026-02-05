rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 52 8B 16 50 51 FF D2 }  // RtlAllocateHeap allocation sequence
        $pattern1 = { 0F 84 ?? ?? ?? ?? }    // Conditional jump to evasion check
        $pattern2 = { 85 C0 0F 84 ?? ?? ?? ?? }  // Test/EAX + JZ evasion logic

    condition:
        any of them
}