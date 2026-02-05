rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+??,action0=skip,bp1=$pattern1+??,action1=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 ?? ?? ?? ?? }
        $pattern1 = { 83 F8 01 74 12 ?? ?? }

    condition:
        any of them
}