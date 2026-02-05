rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved with specific early call/test/je"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? ?? }
        $pattern1 = { 74 12 8B 4D ?? ?? ?? ?? ?? }
        $pattern2 = { 6A 5B 33 CD ?? ?? ?? ?? ?? }
    condition:
        (any of them)
}