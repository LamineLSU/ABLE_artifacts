rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 ?? ?? ?? ?? 8B 45 FC } // CALL TEST EAX pattern
        $pattern1 = { 83 F8 01 74 12 8B 4D F8 } // API CHECK pattern
        $pattern2 = { DC 5A 8B 0C 24 8B 44 24 08 } // TIMING_CHECK pattern

    condition:
        any of them
}