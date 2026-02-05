rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass targeting exit decision points"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? 8B 45 FC }
        $pattern1 = { 8D 43 01 ?? ?? ?? ?? ?? ?? }
        $pattern2 = { 85 C0 74 07 ?? ?? ?? ?? }

    condition:
        any of them
}