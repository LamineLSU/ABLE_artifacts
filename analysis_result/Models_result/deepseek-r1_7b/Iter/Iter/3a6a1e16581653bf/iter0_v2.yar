rule Bypass_Evasion {
    meta:
        description = "Evasion bypass detection through instruction skipping"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 86 C4 FF 00 00 ?? ?? ?? ?? 5E 7D 5A 8B CE E8 FF C0 FF ?? }
        $pattern1 = { B8 C4 11 80 00 00 ?? ?? ?? ?? 3F F6 93 FC FF ?? ?? }
        $pattern2 = { 53 E1 00 00 00 00 ?? ?? ?? ?? C7 00 00 00 00 ?? }

    condition:
        any of them
}