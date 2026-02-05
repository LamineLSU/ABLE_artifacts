rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 84 C0 74 20 64 A1 ?? ?? ?? ?? }
        $pattern1 = { 6A 00 FF 15 ?? ?? ?? ?? }
        $pattern2 = { 57 FF 15 ?? ?? ?? ?? }

    condition:
        any of them
}