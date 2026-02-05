rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved specific to exit decision"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 ?? ?? ?? ?? ?? ?? ?? }

    condition:
        any of them
}