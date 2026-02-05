rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { ?? ?? ?? ?? ?? EA EA }
        $pattern1 = { ?? ?? ?? ?? ?? EA 32 }
        $pattern2 = { ?? ?? ?? ?? ?? CA DD EB 00 00 01 10 }

    condition:
        any of them
}