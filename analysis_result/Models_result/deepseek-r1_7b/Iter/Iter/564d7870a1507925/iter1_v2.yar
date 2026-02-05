rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 83 F8 01 74 ?? ?? ?? ?? ?? }
        $pattern1 = { 6A 00 00 00 5B C3 ?? ?? ?? ?? }
        $pattern2 = { E8 D1 C7 FF ?? ?? ?? ?? ?? }

    condition:
        any of them
}