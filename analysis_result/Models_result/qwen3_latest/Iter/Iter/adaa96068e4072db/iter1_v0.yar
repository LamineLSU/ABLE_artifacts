rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 04 13 00 00 }  // Call to 0041F143h (evasion check)
        $pattern1 = { 52 FF D0 }          // Push edx + Call EAX (RtlFreeHeap)
        $pattern2 = { 8B 5D 14 8B 4D 10 8B 4D 0C 8B 4D 08 8B 4D 04 8B 4D 00 }  // Multiple movs before heap free

    condition:
        any of them
}