rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern1+0,action0=skip,bp2=$pattern2+0,action2=skip,bp3=$pattern3+0,action3=skip,count=0"

    strings:

    condition:
        any of them
}