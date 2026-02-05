rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,count=0"

    strings:
        $pattern0 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? }
        $pattern1 = { FF 75 08 50 FF 15 3C ?? ?? ?? ?? 8B 40 68 FF 15 40 ?? ?? ?? ?? }
        $pattern2 = { 8B 40 68 A8 01 FF 75 08 E8 0B 00 59 FF 75 08 }

    condition:
        any of them
}