rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern1+0,action0=skip,bp1=$pattern2+0,action1=skip,bp2=$pattern3+0,action2=skip,count=0"

    strings:
        $pattern1 = { 55 8B EC FF 75 ?? E8 ?? ?? ?? ?? }
        $pattern2 = { E8 ?? ?? ?? ?? 8B FF 59 FF 75 ?? }
        $pattern3 = { 8B FF 55 8B EC FF 75 ?? 85 C0 }

    condition:
        any of them
}