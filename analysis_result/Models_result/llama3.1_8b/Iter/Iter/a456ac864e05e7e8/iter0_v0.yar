rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 2B E8 ?? ?? ?? ?? }
        $pattern1 = { 8B FF 55 8B EC FF 75 08 FF ?? ?? ?? ?? }
        $pattern2 = { 6A 01 5A 8B CE E8 ?? ?? ?? ?? 85 C0 }

    condition:
        any of them
}