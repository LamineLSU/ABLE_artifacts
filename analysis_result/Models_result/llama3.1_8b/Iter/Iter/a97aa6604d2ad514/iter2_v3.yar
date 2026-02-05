rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B EC 8B 45 08 56 6A 35 6A 00 51 }
        $pattern1 = { FF D0 5E 5D C3 55 8B EC 8B 88 C4 09 00 00 56 6A 36 6A 00 51 E8 04 13 00 00 }
        $pattern2 = { 85 C0 0F 84 ?? ?? ?? ?? 8B 45 FC }

    condition:
        any of them
}