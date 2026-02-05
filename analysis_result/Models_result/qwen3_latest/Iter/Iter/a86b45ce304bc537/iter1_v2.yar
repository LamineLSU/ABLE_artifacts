rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 52 8B 16 50 51 FF D2 }  // RtlAllocateHeap call with context
        $pattern1 = { 8D B0 74 0C 00 00 56 50 E8 ?? ?? ?? ?? }  // Indirect jump to obfuscated code
        $pattern2 = { 08 8B 88 14 0A 00 }  // Memory manipulation on specific offset

    condition:
        any of them
}