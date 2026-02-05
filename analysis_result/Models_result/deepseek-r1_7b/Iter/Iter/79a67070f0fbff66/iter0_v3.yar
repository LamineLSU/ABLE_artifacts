rule Bypass_Sample
{
    meta:
        description = "Evasion bypass detection using multiple patterns"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 45 E4 ?? ?? ?? ?? FF 15 A4 50 61 00 }
        $pattern1 = { E8 BC ?? ?? ?? ?? 8B 45 E0 ?? ?? ?? ?? 8B 55 C4 }
        $pattern2 = { 8B 4D C4 ?? ?? ?? ?? EB CD }

    condition:
        any of them
}