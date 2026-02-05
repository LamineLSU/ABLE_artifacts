rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 64 A1 30 00 00 00 8B 40 68 C1 E8 08 A8 01 75 10 }
        $pattern1 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? 85 C0 }
        $pattern2 = { FF 15 3C E1 91 00 50 FF 15 40 E1 91 00 }

    condition:
        any of them
}