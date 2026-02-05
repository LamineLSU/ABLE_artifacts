rule Bypass_Sample {
    meta:
        description = "Evasion bypass detection using exitProcess calls"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 EA CD ?? EA ?? DD EB 8B 40 13 EA DD E0 13 }
        $pattern1 = { E8 C8 FF FF CA DD 00 40 E7 F6 ?? ?? EB 5A EB FF 75 08 DD EB 08 ?? EA }
        $pattern2 = { E8 C8 FF FF CA DD 00 40 E7 F6 ?? FF 03 C3 AD EA EB ?? EB FF 75 08 DD EB 08 ?? EA }

    condition:
        any of them
}