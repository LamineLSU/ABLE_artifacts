rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule for specific instruction sequences"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip"

    pattern0 = E8 27 ?? ?? ?? ??
    pattern1 = E8 3C ?? ?? ?? ??
    pattern2 = E8 5A ?? ?? ?? ??
}