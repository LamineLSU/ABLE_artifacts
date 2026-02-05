rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 488D4C2460 ?? ?? ?? ?? ??
        $pattern1 = { C744242002000000 ?? ?? ?? ?? ??
        $pattern2 = { FF15E90E0000 ?? ?? ?? ?? ??

    condition:
        any of them
}