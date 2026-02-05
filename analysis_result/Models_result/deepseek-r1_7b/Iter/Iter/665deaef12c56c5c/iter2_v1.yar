rule Bypass_Sample_Evolved {
    meta:
        description = "Evasion bypass rule targeting fixed ExitProcess calls"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8C8FFFFFF 8B EC FF75 08 }
        $pattern1 = { 8B EC FF75 08 FF15 AC B0 41 00 }
        $pattern2 = { FF15 AC B0 41 00 8B EC FF75 08 E8 C8 FFFF }

    condition:
        any of them
}