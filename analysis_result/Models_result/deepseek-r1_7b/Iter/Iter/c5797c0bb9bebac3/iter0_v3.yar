rule Bypass_Sample {
    meta:
        description = "Evasion bypass rules targeting specific instructions"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 ?? ?? ?? ?? 59 }
        $pattern1 = { FF ?? ?? FF 15 AC B0 }
        $pattern2 = { E8 C8 ?? ?? FF 75 ?? }

    condition:
        any of them
}