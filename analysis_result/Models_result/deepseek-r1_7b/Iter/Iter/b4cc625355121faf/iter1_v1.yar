rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 00 EF 61 7A 85 C0 0F 84 ?? ?? ?? ?? }
        $pattern1 = { 00 97 61 7A 85 C0 0F 84 ?? ?? ?? ?? }
        $pattern2 = { 03 D0 ?? ?? ?? ?? ?? ?? }

    condition:
        any of them
}