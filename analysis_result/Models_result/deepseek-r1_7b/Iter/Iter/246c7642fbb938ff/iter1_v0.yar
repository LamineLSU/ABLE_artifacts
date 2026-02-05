rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass using identified patterns"
        cape_options = "bp0=$pattern0+0,bp1=$pattern1+0,bp2=$pattern2+0,action0=skip,action1=skip,action2=skip,count=0"

    strings:

    condition:
        any of them
}