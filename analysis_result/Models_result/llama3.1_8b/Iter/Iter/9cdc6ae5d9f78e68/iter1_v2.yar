rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern0+8,action1=skip,count=0"

    strings:
        $pattern0 = { 83 F8 01 74 12 8B 4D F8 }

    condition:
        any of them
}