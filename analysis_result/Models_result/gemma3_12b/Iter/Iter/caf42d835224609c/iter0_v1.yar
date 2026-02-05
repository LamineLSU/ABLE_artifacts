rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A 00 5A 8B CE E8 ?? ?? ?? ?? 85 C0 }
        $pattern1 = { E8 FB 79 FE FF 33 C0 5A 59 59 64 89 10 }
        $pattern2 = { 33 C0 5A 8B 85 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? }

    condition:
        any of them
}