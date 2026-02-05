rule Malware_Evasion_Bypass {
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { FF 15 2C A1 11 01 53 33 FF 8B C7 EB 03 }
        $pattern1 = { FF 15 2C A1 DB 00 53 33 FF 8B C7 EB 03 }
        $pattern2 = { FF 15 AC B0 41 00 59 FF 75 08 E8 C8 FF FF FF }

    condition:
        any of them
}