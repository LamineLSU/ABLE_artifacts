rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 50 51 FF D2 5E 5D C3 }  // Call to RtlAllocateHeap with surrounding instructions
        $pattern1 = { 52 50 FF D2 5E 5F C3 }  // Call to RtlFreeHeap with surrounding instructions
        $pattern2 = { 8D B0 A0 0A 00 00 }         // Unique LEA instruction with displacement

    condition:
        any of them
}