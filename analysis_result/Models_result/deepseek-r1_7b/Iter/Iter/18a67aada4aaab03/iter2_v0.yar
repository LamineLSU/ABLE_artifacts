rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule targeting specific instruction sequences"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip"

    pattern_0:
        E8 F7 25 ?? ??
        
    pattern_1:
        74 ?? ??????

    pattern_2:
        E8E6 ??????
}