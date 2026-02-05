rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 7C 8C 6A ?? }
        $pattern1 = { E8 9D 0E 4B F8 43 ?? FF 0F 85 C0 0F 84 FF 25 ?? 8B 45 FE EC 00 00 00 00 }
        $pattern2 = { 6A 5A 8B CE E8 73 ?? 53 ?? 8D 8D F8 FE 00 00 14 60 FF 15 88 A1 16 7F 26 00 00 00 00 00 00 00 00 00 8B E5 88 A0 11 40 00 00 00 00 00 }
    condition:
        any of them
}