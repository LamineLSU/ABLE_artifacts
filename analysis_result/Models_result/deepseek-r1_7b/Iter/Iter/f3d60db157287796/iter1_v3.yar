rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule - focused on strategic points before exit"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? E8 C8 FF FF FF }
        $pattern1 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? FF 75 08 }
        $pattern2 = { 8B FF 55 8B EC ?? ?? FF 75 08 ?? }

    condition:
        any of them
}