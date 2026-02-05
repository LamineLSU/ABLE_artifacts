rule Evasion_Bypass_Patterns {
    meta:
        description = "Evasion bypass patterns targeting specific instructions"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 55 0C 5E 5D EB 50 EA 56 }
        $pattern1 = { 8B 45 10 E8 74 0A 00 00 CA EA ?? ?? ?? }
        $pattern2 = { 6A 00 00 00 00 00 8B 45 10 EA DD EB 10 ?? }

    condition:
        any of them
}