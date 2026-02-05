rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 50 E8 04 13 00 00 } // Call to 0041F143h (evasion check)
        $pattern1 = { 50 51 FF D2 }        // Call to RtlFreeHeap (resource cleanup)
        $pattern2 = { 51 8D B0 A0 0A 00 00 } // LEA instruction with offset (memory manipulation)

    condition:
        any of them
}