rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { FF 15 84 94 45 00 8D 95 94 FE FF FF }
        $pattern1 = { FF 15 84 94 45 00 8B 45 9C 8B CE E8 ?? ?? ?? ?? 85 C0 }
        $pattern2 = { 8D 95 94 FE FF FF 8D 8D EC FE FF FF 52 C7 85 94 FE FF FF 3C }

    condition:
        any of them
}