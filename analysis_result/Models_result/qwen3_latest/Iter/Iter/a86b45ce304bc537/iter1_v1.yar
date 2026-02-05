rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { FF D2 5E 5D C3 }  // RtlFreeHeap call + cleanup
        $pattern1 = { E8 ?? ?? ?? ?? 8B 55 14 }  // Indirect call to evasion check
        $pattern2 = { A3 D6 DB E4 B1 }  // Unique memory write operation

    condition:
        any of them
}