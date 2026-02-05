rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? 85 C0 }
        $pattern1 = { 8B FF 55 8B EC 8B E5 83 EC ?? 8B 45 ?? }
        $pattern2 = { E8 C8 FF FF FF 59 FF 75 08 FF 15 AC B0 41 00 }

    condition:
        any of them
}