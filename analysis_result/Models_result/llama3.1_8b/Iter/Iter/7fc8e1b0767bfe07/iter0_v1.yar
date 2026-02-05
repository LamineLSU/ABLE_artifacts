rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8D 42 ?? E8 ?? ?? ?? ?? C9 }
        $pattern1 = { 8B FF 55 8B EC F6 44 ?? 02 85 C0 74 ?? }
        $pattern2 = { 56 57 6A ?? 58 8B CE 83 E4 ?? FF 15 ?? ?? ?? }

    condition:
        any of them
}