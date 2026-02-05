rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { A9 C5 1E B6 55 85 C0 ?? ?? ?? ?? }
        $pattern1 = { 56 6A ?? 5A 8B CE E8 ?? ?? ?? ?? }
        $pattern2 = { FF D0 C3 EE 79 B4 1E 7C C0 4B 59 10 72 29 22 CD 37 }

    condition:
        any of them
}