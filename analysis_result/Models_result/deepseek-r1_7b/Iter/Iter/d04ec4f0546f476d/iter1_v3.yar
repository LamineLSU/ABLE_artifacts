rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - improved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 40 68 ?? ?? ?? ?? ?? }
        $pattern1 = { E8 73 D0 00 00 00 ?? ?? ?? ?? ?? }
        $pattern2 = { C1 E8 08 ?? ?? ?? ?? ?? }

    condition:
        any of them
}