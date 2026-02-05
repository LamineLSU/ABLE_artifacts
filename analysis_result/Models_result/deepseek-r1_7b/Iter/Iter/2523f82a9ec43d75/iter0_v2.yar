rule Bypass_Sample {
    meta:
        description = "Evasion bypass analysis"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 E8 CE ?? ?? ?? ?? BA 1D F0 FE }
        $pattern1 = { FF 75 08 ?? 00 00 00 00 8B CC 8C 3F ?? }
        $pattern2 = { BA 21 05 00 00 6A 40 00 00 53 5D ?? C8 70 F9 F0 FF 15 2C A1 00 00 }

    condition:
        any_ofthem
}