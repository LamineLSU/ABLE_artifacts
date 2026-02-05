rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A 5B 5A 8B CE E8 ?? ?? ?? ?? 85 C0 }
        $pattern1 = { FF 15 8C E1 19 00 85 C0 0F 84 ?? ?? ?? ?? }
        $pattern2 = { 6A 40 53 68 40 11 0C 01 33 C9 E8 4B 17 00 00 }

    condition:
        any of them
}