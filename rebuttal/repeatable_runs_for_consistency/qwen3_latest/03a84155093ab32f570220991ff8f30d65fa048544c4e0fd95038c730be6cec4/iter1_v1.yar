rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 50 51 FF D2 5E 5D C3 } // API call setup and cleanup
        $pattern1 = { 8B 45 F8 E8 44 09 00 00 }   // Call to 0041AF50h
        $pattern2 = { 94 99 AD 77 B8 0A 04 B6 } // Conditional jump and register manipulation

    condition:
        any of them
}