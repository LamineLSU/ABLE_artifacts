rule Bypass_Sample {
    meta:
        description = "Evasion bypass patterns targeting specific instructions"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 F7 25 00 00 FF 75 08 00 41 B9 1E A8 01 74 20 64 A1 30 00 00 00 8B 40 68 C1 E8 08 FF 75 08 }
        $pattern1 = { E8 F7 25 00 00 FF 75 08 C1 E8 08 A8 01 74 20 83 F8 01 FF 75 08 FF 15 A0 F1 42 00 }
        $pattern2 = { FF 75 08 FF 75 08 E8 F7 25 00 00 C1 E8 08 A8 01 74 20 64 A1 30 00 00 00 8B 40 68 FF 75 08 }
}

condition:
    any
}