rule Bypass_Sample {
    meta: description = "Evasion bypass detection using TEST and JUMP instructions"
    cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 ?? 5A 8B CE E8 25 05 00 00 ?? }
        $pattern1 = { FF 75 08 8B EC 5A 8B 40 68 A8 01 C1 E8 ?? 00 00 01 04 }
        $pattern2 = { 6A 40 53 E8 0D 0C 00 00 ?? FF 75 08 8B E5 ?? 00 14 8C 42 }

    condition: any
}