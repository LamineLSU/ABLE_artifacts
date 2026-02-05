rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - specifically targeting TEST EAX followed by conditional jumps"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:

    condition:
        any of them
}