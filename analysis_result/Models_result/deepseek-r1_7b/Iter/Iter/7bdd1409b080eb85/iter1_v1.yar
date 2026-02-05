rule Bypass_Sample_Evolved
{
    meta:
        description = "Bypass YARA rules for evasion"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 68 1C 27 47 85 C0 74 16 }
        $pattern1 = { 68 1C 27 47 85 C0 74 16 FF 74 24 04 00 00 00 00 }  // Different offset
        $pattern2 = { FF 74 24 04 00 00 00 01 00 00 00 00 00 00 00 03 00 00 00 00 }  // Unique conditional
}

condition:
    any of them