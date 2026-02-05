rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A 00 5A 8B CE E8 ?? ?? ?? ?? 85 C0 }
        $pattern1 = { E8 72 E5 FF FF 8B 85 4C F2 FF FF }
        $pattern2 = { E8 E7 E9 FF FF A1 AC 5B 35 02 }

    condition:
        any of them
}