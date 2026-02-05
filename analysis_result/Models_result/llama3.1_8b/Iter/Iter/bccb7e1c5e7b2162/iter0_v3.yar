rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=8D ?? FE FF FF 89 ?? DF ?? FE FF+0,action0=skip,bp1=89 ?9 DF FE FF FF 8B CE E8 ?? ?? ?? ?? 85 C0+0,action1=skip,bp2=8D95 F0 FE FF FF 8B CE E8 ?? ?? ?? ?? 85 C0+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8D ?? FE FF FF 89 ?? DF ?? FE FF }
        $pattern1 = { 89 DF FE FF FF 8B CE E8 ?? ?? ?? ?? 85 C0 }
        $pattern2 = { 8D 95 F0 FE FF FF 8B CE E8 ?? ?? ?? ?? 85 C0 }

    condition:
        any of them
}