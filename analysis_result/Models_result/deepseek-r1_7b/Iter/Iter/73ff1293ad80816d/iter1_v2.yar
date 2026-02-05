rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass targeting exit decision points"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,count=0"

    strings:
        $pattern0 = { 3D 02 05 48 C7 ?? }
        $pattern1 = { 8B 4D F8 FE FF 0F }

    condition:
        any of them
}