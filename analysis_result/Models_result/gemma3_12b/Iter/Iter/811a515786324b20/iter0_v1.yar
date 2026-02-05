rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 5A 8B CE E8 ?? ?? ?? ?? 85 C0 }
        $pattern1 = { 8D 85 D4 FE FF FF 50 A1 64 B5 41 00 }
        $pattern2 = { A1 64 B5 41 00 8B 00 FF D0 }

    condition:
        any of them
}