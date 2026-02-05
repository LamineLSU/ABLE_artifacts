rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B FF 55 8B EC FF 75 08 }
        $pattern1 = { FF 15 ?? ?? ?? ?? 8B FF 55 8B EC }
        $pattern2 = { 8B 45 ?? 85 C0 0F 84 ?? ?? ?? ?? }

    condition:
        any of them
}