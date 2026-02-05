rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,count=0"

    strings:
        $pattern0 = { 00 FA 61 2C ?? ?? ?? ?? ?? ?? }
        $pattern1 = { 8B FF ?? ?? ?? ?? ?? ?? }

    condition:
        any of them
}