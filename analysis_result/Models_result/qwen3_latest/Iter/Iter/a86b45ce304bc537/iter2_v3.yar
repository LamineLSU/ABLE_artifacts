rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { FF D2 5E 5D C3 } // RtlAllocateHeap followed by stack cleanup
        $pattern1 = { FF D2 55 8B EC 8B 55 08 } // RtlFreeHeap followed by register setup
        $pattern2 = { 1C CE A3 D6 DB E4 B1 } // sbb + mov sequence for data manipulation

    condition:
        any of them
}