rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,count=0"

    strings:
        $pattern0 = { CA 74 ?? ?? ?? ?? ?? }
        $pattern1 = { EA 75 ?? ?? ?? ?? }
        $pattern2 = { EE ?? ?? ?? ?? ?? }

    condition:
        any of them
}