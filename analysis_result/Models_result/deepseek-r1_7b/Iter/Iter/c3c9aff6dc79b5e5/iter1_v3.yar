rule Bypass_Sample_Evolved {
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 83 7D 10 00 CD EB 10 00 00 00 00 EF }
        $pattern1 = { FF 15 98 44 41 00 CA DD 00 41 44 98 DD 00 41 44 70 EA 00 02 5A 6C }
        $pattern2 = { FF 35 D4 B0 41 00 DD 00 41 B0 D8 FF 15 70 44 41 00 CA DD 00 41 44 90 EA 00 02 5A 6C }
    condition:
        any of them
}